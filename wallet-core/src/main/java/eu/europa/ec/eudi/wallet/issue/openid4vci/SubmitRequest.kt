/*
 * Copyright (c) 2024-2025 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.wallet.issue.openid4vci

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest
import eu.europa.ec.eudi.openid4vci.BatchSignOperation
import eu.europa.ec.eudi.openid4vci.BatchSigner
import eu.europa.ec.eudi.openid4vci.IssuanceRequestPayload
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.JwtBindingKey
import eu.europa.ec.eudi.openid4vci.KeyAttestationJWT
import eu.europa.ec.eudi.openid4vci.ProofSpecification
import eu.europa.ec.eudi.openid4vci.ProofType
import eu.europa.ec.eudi.openid4vci.ProofTypeMeta
import eu.europa.ec.eudi.openid4vci.ProofTypesSupported
import eu.europa.ec.eudi.openid4vci.SignOperation
import eu.europa.ec.eudi.openid4vci.SubmissionOutcome
import eu.europa.ec.eudi.wallet.document.UnsignedDocument
import eu.europa.ec.eudi.wallet.document.credential.ProofOfPossessionSigner
import eu.europa.ec.eudi.wallet.provider.WalletKeyAttestationProvider
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData

internal class SubmitRequest(
    val walletKeyAttestationProvider: WalletKeyAttestationProvider?,
    val issuer: Issuer,
    authorizedRequest: AuthorizedRequest,
) {
    var authorizedRequest: AuthorizedRequest = authorizedRequest
        private set

    suspend fun request(offeredDocuments: Map<UnsignedDocument, Offer.OfferedDocument>): Response {
        return Response(offeredDocuments.mapValues { (unsignedDocument, offeredDocument) ->
            try {
                val (keyAliases, outcome) = submitRequest(unsignedDocument, offeredDocument)
                ResponseResult(
                    keyAliases = keyAliases,
                    outcome = Result.success(outcome)
                )
            } catch (e: Throwable) {
                ResponseResult(emptyList(), Result.failure(e))
            }
        })
    }

    private suspend fun submitRequest(
        unsignedDocument: UnsignedDocument,
        offeredDocument: Offer.OfferedDocument,
        keyUnlockData: Map<KeyAlias, KeyUnlockData?>? = null,
    ): ResponseResult<SubmissionOutcome> {
        val payload =
            IssuanceRequestPayload.ConfigurationBased(offeredDocument.configurationIdentifier)
        val signers = unsignedDocument.getPoPSigners()
        val proofTypesSupported = offeredDocument.configuration.proofTypesSupported
        val jwtProof = proofTypesSupported[ProofType.JWT] as? ProofTypeMeta.Jwt

        val (updatedAuthorizedRequest, outcome) = when {
            // Issuer requires no proof
            proofTypesSupported == ProofTypesSupported.Empty -> {
                with(issuer) {
                    authorizedRequest.request(payload, ProofSpecification.NoProof)
                }.getOrThrow()
            }
            // Attestation proof (if provider available & issuer supports it)
            proofTypesSupported[ProofType.ATTESTATION] != null && walletKeyAttestationProvider != null -> {
                requestWithAttestationProof(payload, signers)
            }
            // JWT proof with key attestation (if provider available & issuer supports it)
            jwtProof?.keyAttestationRequirement != null && walletKeyAttestationProvider != null -> {
                authorizedRequest.requestWithJwtProofWithKeyAttestation(
                    payload, signers, keyUnlockData,
                    unlockResume = { updatedKeyUnlockData ->
                        submitRequest(unsignedDocument, offeredDocument, updatedKeyUnlockData)
                    }
                )
            }
            jwtProof != null && jwtProof.keyAttestationRequirement == null -> {
                authorizedRequest.requestWithJwtProofsWithoutKeyAttestation(
                    payload, signers, keyUnlockData,
                    unlockResume = { updatedKeyUnlockData ->
                        submitRequest(unsignedDocument, offeredDocument, updatedKeyUnlockData)
                    }
                )
            }
            //  KeyAttestationProvider is null
            else -> error("Issuer requires proofs but no WalletKeyAttestationProvider is available")
        }

        this.authorizedRequest = updatedAuthorizedRequest
        return ResponseResult(
            keyAliases = signers.map { it.keyAlias },
            outcome = outcome
        )
    }

    private suspend fun requestWithAttestationProof(
        payload: IssuanceRequestPayload,
        signers: List<ProofOfPossessionSigner>,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {
        val walletKeyAttestationProvider = checkNotNull(walletKeyAttestationProvider) {
            "WalletKeyAttestationProvider is required for attestation proof"
        }
        val proofsSpecification = ProofSpecification.AttestationProof { nonce, _ ->
            walletKeyAttestationProvider.getKeyAttestation(
                signers.map { it.getKeyInfo() },
                nonce
            )
                .map { KeyAttestationJWT(it) }
                .getOrThrow()
        }
        return authorizedRequest.requestWithAttestationProof(payload, proofsSpecification)
    }

    class Response(map: Map<UnsignedDocument, ResponseResult<Result<SubmissionOutcome>>>) :
        Map<UnsignedDocument, ResponseResult<Result<SubmissionOutcome>>> by map

    data class ResponseResult<T>(
        val keyAliases: List<String>,
        val outcome: T,
    )

    private suspend fun AuthorizedRequest.requestWithAttestationProof(
        payload: IssuanceRequestPayload,
        proofsSpecification: ProofSpecification.AttestationProof,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {
        return with(issuer) {
            request(payload, proofsSpecification)
        }.getOrThrow()
    }

    private suspend fun AuthorizedRequest.requestWithJwtProofWithKeyAttestation(
        payload: IssuanceRequestPayload,
        signers: List<ProofOfPossessionSigner>,
        keyUnlockData: Map<String, KeyUnlockData?>?,
        unlockResume: suspend (Map<String, KeyUnlockData?>) -> ResponseResult<SubmissionOutcome>,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {
        val walletKeyAttestationProvider = checkNotNull(walletKeyAttestationProvider) {
            "WalletKeyAttestationProvider is required for JWT proof with key attestation"
        }
        var proofSigner: KeyAttestationSigner? = null
        val proofsSpecification = ProofSpecification.JwtProofWithKeyAttestation(
            proofSignerProvider = { nonce, _ ->
                val factory = KeyAttestationSigner.Factory(
                    signers, walletKeyAttestationProvider, keyUnlockData
                )
                factory(nonce).getOrThrow().also { proofSigner = it }
            }
        )
        try {
            return with(issuer) { request(payload, proofsSpecification) }.getOrThrow()
        } catch (e: Throwable) {

            val isUserAuthRequired = proofSigner?.keyLockedException != null
            if (isUserAuthRequired) {
                val keysAndSecureAreas = mapOf(
                    proofSigner.signer.let { it.keyAlias to it.secureArea }
                )
                throw UserAuthRequiredException(
                    signingAlgorithm = proofSigner.signer.getKeyInfo().algorithm,
                    keysAndSecureAreas = keysAndSecureAreas,
                    resume = { keyUnlockData ->
                        unlockResume(keyUnlockData)
                    },
                    cause = e
                )
            } else {
                throw e
            }
        }

    }

    private suspend fun AuthorizedRequest.requestWithJwtProofsWithoutKeyAttestation(
        payload: IssuanceRequestPayload,
        signers: List<ProofOfPossessionSigner>,
        keyUnlockData: Map<String, KeyUnlockData?>?,
        unlockResume: suspend (Map<String, KeyUnlockData?>) -> ResponseResult<SubmissionOutcome>,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {
        val proofSigner = JwtProofsSigner(signers, keyUnlockData)
        val proofsSpecification = ProofSpecification.JwtProofsWithoutKeyAttestation(proofSigner)
        try {
            return with(issuer) { request(payload, proofsSpecification) }.getOrThrow()
        } catch (e: Throwable) {
            if (proofSigner.keyLockedException == null) throw e
            throw UserAuthRequiredException(
                signingAlgorithm = proofSigner.algorithm,
                keysAndSecureAreas = signers.associate { it.keyAlias to it.secureArea },
                resume = { keyUnlockData ->
                    unlockResume(keyUnlockData)
                },
                cause = e
            )
        }
    }

}

private class JwtProofsSigner private constructor(
    private val signers: List<ProofOfPossessionSigner>,
    val algorithm: Algorithm,
    private val keyUnlockData: Map<KeyAlias, KeyUnlockData?>?,
) : BatchSigner<JwtBindingKey> {

    override val javaAlgorithm: String = requireNotNull(algorithm.javaAlgorithm) {
        "No JCA algorithm name for ${algorithm.name}"
    }

    var keyLockedException: KeyLockedException? = null
        private set

    override suspend fun authenticate(): BatchSignOperation<JwtBindingKey> =
        BatchSignOperation(signers.map { signer ->
            val signerKeyUnlockData = keyUnlockData?.get(signer.keyAlias)
            SignOperation(
                function = { input ->
                    try {
                        signer.signPoP(input, signerKeyUnlockData).toDerEncoded()
                    } catch (e: KeyLockedException) {
                        keyLockedException = e
                        throw e
                    }
                },
                publicMaterial = JwtBindingKey.Jwk(
                    JWK.parse(signer.getKeyInfo().publicKey.toJwk().toString())
                ),
            )
        })

    override suspend fun release(signOps: BatchSignOperation<JwtBindingKey>?) = Unit

    companion object {
        suspend operator fun invoke(
            signers: List<ProofOfPossessionSigner>,
            keyUnlockData: Map<KeyAlias, KeyUnlockData?>?,
        ): JwtProofsSigner = JwtProofsSigner(
            signers = signers,
            algorithm = signers.first().getKeyInfo().algorithm,
            keyUnlockData = keyUnlockData,
        )
    }
}
