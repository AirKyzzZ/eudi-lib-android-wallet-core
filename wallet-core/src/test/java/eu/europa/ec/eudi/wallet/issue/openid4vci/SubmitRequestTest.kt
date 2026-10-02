package eu.europa.ec.eudi.wallet.issue.openid4vci

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest
import eu.europa.ec.eudi.openid4vci.CredentialConfiguration
import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.JwtBindingKey
import eu.europa.ec.eudi.openid4vci.KeyAttestationRequirement
import eu.europa.ec.eudi.openid4vci.ProofSpecification
import eu.europa.ec.eudi.openid4vci.ProofTypeMeta
import eu.europa.ec.eudi.openid4vci.ProofTypesSupported
import eu.europa.ec.eudi.openid4vci.SubmissionOutcome
import eu.europa.ec.eudi.wallet.document.UnsignedDocument
import eu.europa.ec.eudi.wallet.document.credential.ProofOfPossessionSigner
import eu.europa.ec.eudi.wallet.document.credential.ProofOfPossessionSigners
import eu.europa.ec.eudi.wallet.provider.WalletKeyAttestationProvider
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcSignature
import org.multipaz.prompt.Reason
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.robolectric.RobolectricTestRunner
import java.security.Signature
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
class SubmitRequestTest {

    private val authorizedRequest = mockk<AuthorizedRequest>()
    private val successOutcome = mockk<SubmissionOutcome.Success>()
    private val proofSpecification = slot<ProofSpecification>()
    private val signedInputs = mutableListOf<Pair<JWK, ByteArray>>()

    private val issuer = mockk<Issuer> {
        coEvery {
            any<AuthorizedRequest>().request(any(), capture(proofSpecification))
        } coAnswers {
            runCatching {
                val spec = proofSpecification.captured
                if (spec is ProofSpecification.JwtProofsWithoutKeyAttestation) {
                    spec.proofSigner.authenticate().operations.forEach { operation ->
                        val jwk = assertIs<JwtBindingKey.Jwk>(operation.publicMaterial).jwk
                        signedInputs += jwk to operation.function.sign(SIGNING_INPUT)
                    }
                }
                authorizedRequest to successOutcome
            }
        }
    }

    @Test
    fun `jwt proof without key attestation signs one proof per document key`() = runTest {
        val signers = createSigners(count = 2)

        val result = submit(jwtProof(keyAttestationRequirement = null), signers)

        assertEquals(successOutcome, result.outcome.getOrThrow())
        assertEquals(signers.map { it.keyAlias }, result.keyAliases)
        val spec = assertIs<ProofSpecification.JwtProofsWithoutKeyAttestation>(proofSpecification.captured)
        assertEquals("SHA256withECDSA", spec.proofSigner.javaAlgorithm)
        assertEquals(
            signers.map { JWK.parse(it.getKeyInfo().publicKey.toJwk().toString()) },
            signedInputs.map { it.first },
        )
        signedInputs.forEach { (jwk, signature) ->
            assertTrue(jwk.verifies(signature))
        }
    }

    @Test
    fun `jwt proof without key attestation is used even when a key attestation provider is set`() =
        runTest {
            submit(
                jwtProof(keyAttestationRequirement = null),
                createSigners(count = 1),
                walletKeyAttestationProvider = mockk(),
            )

            assertIs<ProofSpecification.JwtProofsWithoutKeyAttestation>(proofSpecification.captured)
        }

    @Test
    fun `jwt proof requiring key attestation uses the key attestation provider`() = runTest {
        submit(
            jwtProof(keyAttestationRequirement = KeyAttestationRequirement(null, null, null)),
            createSigners(count = 1),
            walletKeyAttestationProvider = mockk(),
        )

        assertIs<ProofSpecification.JwtProofWithKeyAttestation>(proofSpecification.captured)
    }

    @Test
    fun `jwt proof requiring key attestation fails without a key attestation provider`() = runTest {
        val result = submit(
            jwtProof(keyAttestationRequirement = KeyAttestationRequirement(null, null, null)),
            createSigners(count = 1),
        )

        assertIs<IllegalStateException>(result.outcome.exceptionOrNull())
        coVerify(exactly = 0) { with(issuer) { any<AuthorizedRequest>().request(any(), any()) } }
    }

    @Test
    fun `locked key asks for user auth on every document key and resumes with unlock data`() =
        runTest {
            val signers = createSigners(count = 2, locked = true)

            val result = submit(jwtProof(keyAttestationRequirement = null), signers)

            val exception = assertIs<UserAuthRequiredException>(result.outcome.exceptionOrNull())
            assertEquals(Algorithm.ESP256, exception.signingAlgorithm)
            assertEquals(signers.map { it.keyAlias }.toSet(), exception.keysAndSecureAreas.keys)

            val resumed = exception.resume(signers.associate { it.keyAlias to mockk<KeyUnlockData>() })

            assertEquals(successOutcome, resumed.outcome)
            assertEquals(signers.size, signedInputs.size)
        }

    private suspend fun submit(
        proofTypes: ProofTypesSupported,
        signers: List<ProofOfPossessionSigner>,
        walletKeyAttestationProvider: WalletKeyAttestationProvider? = null,
    ): SubmitRequest.ResponseResult<Result<SubmissionOutcome>> {
        val unsignedDocument = mockk<UnsignedDocument> {
            coEvery { getPoPSigners() } returns ProofOfPossessionSigners(signers)
        }
        val offeredDocument = mockk<Offer.OfferedDocument> {
            every { configurationIdentifier } returns CredentialConfigurationIdentifier("id")
            every { configuration } returns mockk<CredentialConfiguration> {
                every { proofTypesSupported } returns proofTypes
            }
        }
        val response = SubmitRequest(walletKeyAttestationProvider, issuer, authorizedRequest)
            .request(mapOf(unsignedDocument to offeredDocument))
        return response.getValue(unsignedDocument)
    }

    private fun jwtProof(keyAttestationRequirement: KeyAttestationRequirement?) =
        ProofTypesSupported(
            setOf(ProofTypeMeta.Jwt(listOf(JWSAlgorithm.ES256), keyAttestationRequirement))
        )

    private suspend fun createSigners(count: Int, locked: Boolean = false): List<ProofOfPossessionSigner> {
        val secureArea = SoftwareSecureArea.create(EphemeralStorage())
        val settings = SoftwareCreateKeySettings.Builder().setAlgorithm(Algorithm.ESP256).build()
        return List(count) {
            SoftwareKeySigner(secureArea, secureArea.createKey(null, settings).alias, locked)
        }
    }

    private fun JWK.verifies(derSignature: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(toECKey().toECPublicKey())
            update(SIGNING_INPUT)
            verify(derSignature)
        }

    private class SoftwareKeySigner(
        override val secureArea: SecureArea,
        override val keyAlias: String,
        private val locked: Boolean,
    ) : ProofOfPossessionSigner {

        override suspend fun getKeyInfo(): KeyInfo = secureArea.getKeyInfo(keyAlias)

        override suspend fun signPoP(dataToSign: ByteArray, keyUnlockData: KeyUnlockData?): EcSignature {
            if (locked && keyUnlockData == null) throw KeyLockedException("locked")
            return secureArea.sign(keyAlias, dataToSign, Reason.Unspecified)
        }
    }

    private companion object {
        val SIGNING_INPUT = "header.payload".toByteArray()
    }
}
