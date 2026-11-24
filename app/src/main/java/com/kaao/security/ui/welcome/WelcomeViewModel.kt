package com.kaao.security.ui.welcome

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.domain.usecase.SmartScanOrchestrator
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class WelcomeViewModel @Inject constructor(
    private val prefs: KaaoPreferencesRepository,
    private val smartScanOrchestrator: SmartScanOrchestrator
) : ViewModel() {

    fun completeOnboarding(runSmartScan: Boolean, onCompleted: () -> Unit) {
        viewModelScope.launch {
            prefs.setOnboardingCompleted(true)
            onCompleted()
            if (runSmartScan) {
                smartScanOrchestrator.runConcurrentSmartScan()
            }
        }
    }
}
