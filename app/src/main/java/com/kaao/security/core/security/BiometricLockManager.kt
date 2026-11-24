package com.kaao.security.core.security

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Hardware BiometricPrompt security lock manager supporting strong biometrics and device PIN/pattern fallback
 * cleanly across API 26–35.
 */
@Singleton
class BiometricLockManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    fun canAuthenticate(): Boolean {
        val bm = BiometricManager.from(context)
        val authenticators = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        }
        return bm.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun capabilityLabel(): String {
        val bm = BiometricManager.from(context)
        val strong = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        return when {
            strong == BiometricManager.BIOMETRIC_SUCCESS -> "Hardware Biometric Ready"
            canAuthenticate() -> "Biometric / Device PIN Ready"
            else -> "No Lock Screen Enrolled"
        }
    }

    fun authenticate(
        activity: FragmentActivity,
        title: String = "Unlock KAAO Security Vault",
        subtitle: String = "Verify your identity to access KAAO controls & encrypted vault",
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                onSuccess()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                onError(errString.toString())
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)
        val promptBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            promptBuilder.setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
        } else {
            @Suppress("DEPRECATION")
            promptBuilder.setDeviceCredentialAllowed(true)
        }

        runCatching {
            prompt.authenticate(promptBuilder.build())
        }.onFailure { err ->
            onError(err.message ?: "Biometric authentication unavailable")
        }
    }
}
