package com.kaao.security.ui.welcome

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CleaningServices
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.SportsEsports
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.kaao.security.ui.components.CyberGradientButton
import com.kaao.security.ui.theme.KaaoColors

@Composable
fun WelcomeScreen(
    onFinished: () -> Unit,
    viewModel: WelcomeViewModel = hiltViewModel()
) {
    val scrollState = rememberScrollState()

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF0A1424),
                        KaaoColors.ObsidianBg,
                        Color(0xFF0B0A18)
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(horizontal = 20.dp, vertical = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(12.dp))

            // Animated Pulsing KAAO Cyber Shield Crest
            PulsingKaaoShieldCrest(modifier = Modifier.size(144.dp))

            Spacer(modifier = Modifier.height(14.dp))

            // Gradient KAAO Wordmark
            Text(
                text = "KAAO",
                style = TextStyle(
                    brush = KaaoColors.BrandWordmarkGradient,
                    fontSize = 42.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 6.sp
                )
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Zero-Root Android Security, Privacy & Performance Suite",
                style = MaterialTheme.typography.bodyMedium,
                color = KaaoColors.TextSecondary,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(24.dp))

            // 4 Color-Coded Capability Pillars
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                CapabilityPillarCard(
                    icon = Icons.Outlined.Security,
                    title = "Antivirus & Stalkerware Audit",
                    description = "Lock-free SHA-256 Bloom Filter, SQLCipher AES-256 vault, DEX/APK static heuristics & active privilege auditing.",
                    accent = KaaoColors.CyberEmerald,
                    container = KaaoColors.CyberEmeraldContainer
                )
                CapabilityPillarCard(
                    icon = Icons.Outlined.VpnLock,
                    title = "Aegis Zero-Root DoH Shield",
                    description = "Split-routed RFC 8484 DNS-over-HTTPS phishing/malware sinkhole, persistent custom rules & Wi-Fi Inspector.",
                    accent = KaaoColors.ShieldCyan,
                    container = KaaoColors.ShieldCyanContainer
                )
                CapabilityPillarCard(
                    icon = Icons.Outlined.CleaningServices,
                    title = "Deep Storage Cleaner",
                    description = "3-stage SHA-256 duplicate finder, leftover APKs, StorageStatsManager cache view & explicit delete confirmation.",
                    accent = KaaoColors.CleanerCobalt,
                    container = KaaoColors.CleanerContainer
                )
                CapabilityPillarCard(
                    icon = Icons.Outlined.SportsEsports,
                    title = "Game Booster & Firewall",
                    description = "Zero-root background bandwidth firewall with voice-chat exceptions, live telemetry HUD & reversible system tweaks.",
                    accent = KaaoColors.BoosterViolet,
                    container = KaaoColors.BoosterVioletContainer
                )
            }

            Spacer(modifier = Modifier.height(28.dp))

            CyberGradientButton(
                text = "Launch & Run Smart Scan",
                icon = Icons.Outlined.Radar,
                brush = Brush.horizontalGradient(
                    listOf(KaaoColors.CyberEmerald, KaaoColors.ShieldCyan, KaaoColors.CleanerCobalt)
                ),
                onClick = {
                    viewModel.completeOnboarding(runSmartScan = true, onCompleted = onFinished)
                }
            )

            Spacer(modifier = Modifier.height(8.dp))

            TextButton(
                onClick = {
                    viewModel.completeOnboarding(runSmartScan = false, onCompleted = onFinished)
                }
            ) {
                Text(
                    text = "Explore Dashboard First",
                    style = MaterialTheme.typography.bodyMedium,
                    color = KaaoColors.TextSecondary
                )
            }
        }
    }
}

@Composable
fun PulsingKaaoShieldCrest(modifier: Modifier = Modifier) {
    val transition = rememberInfiniteTransition(label = "kaao_shield_pulse")
    val pulseRadiusFactor by transition.animateFloat(
        initialValue = 0.72f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1900, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_radius"
    )
    val pulseAlpha by transition.animateFloat(
        initialValue = 0.55f,
        targetValue = 0.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1900, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_alpha"
    )
    val glowPulse by transition.animateFloat(
        initialValue = 0.22f,
        targetValue = 0.45f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "crest_glow"
    )

    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val center = Offset(w / 2f, h / 2f)
        val minDim = size.minDimension

        // Ambient radial cyber aura
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    KaaoColors.CyberEmerald.copy(alpha = glowPulse),
                    KaaoColors.ShieldCyan.copy(alpha = glowPulse * 0.45f),
                    Color.Transparent
                ),
                center = center,
                radius = minDim * 0.52f
            ),
            radius = minDim * 0.52f,
            center = center
        )

        // Expanding radar shockwave ring
        drawCircle(
            color = KaaoColors.ShieldCyan.copy(alpha = pulseAlpha),
            radius = (minDim * 0.48f) * pulseRadiusFactor,
            center = center,
            style = Stroke(width = 2.2.dp.toPx())
        )

        // Inner hexagonal shield body
        val shieldPath = Path().apply {
            moveTo(w * 0.50f, h * 0.14f)
            lineTo(w * 0.80f, h * 0.26f)
            lineTo(w * 0.80f, h * 0.54f)
            cubicTo(w * 0.80f, h * 0.72f, w * 0.66f, h * 0.83f, w * 0.50f, h * 0.89f)
            cubicTo(w * 0.34f, h * 0.83f, w * 0.20f, h * 0.72f, w * 0.20f, h * 0.54f)
            lineTo(w * 0.20f, h * 0.26f)
            close()
        }

        drawPath(
            path = shieldPath,
            brush = Brush.verticalGradient(
                colors = listOf(Color(0xFF0E2A42), Color(0xFF091426))
            )
        )
        drawPath(
            path = shieldPath,
            brush = Brush.linearGradient(
                colors = listOf(KaaoColors.CyberEmerald, KaaoColors.ShieldCyan, KaaoColors.BoosterViolet)
            ),
            style = Stroke(
                width = 3.2.dp.toPx(),
                cap = StrokeCap.Round,
                join = StrokeJoin.Round
            )
        )

        // Stylized geometric "K" emblem inside shield
        val kSpine = Path().apply {
            moveTo(w * 0.38f, h * 0.36f)
            lineTo(w * 0.44f, h * 0.36f)
            lineTo(w * 0.44f, h * 0.68f)
            lineTo(w * 0.38f, h * 0.68f)
            close()
        }
        drawPath(path = kSpine, color = KaaoColors.CyberEmerald)

        val kArms = Path().apply {
            moveTo(w * 0.44f, h * 0.52f)
            lineTo(w * 0.59f, h * 0.36f)
            lineTo(w * 0.67f, h * 0.36f)
            lineTo(w * 0.52f, h * 0.52f)
            lineTo(w * 0.68f, h * 0.68f)
            lineTo(w * 0.59f, h * 0.68f)
            close()
        }
        drawPath(
            path = kArms,
            brush = Brush.horizontalGradient(listOf(KaaoColors.ShieldCyan, KaaoColors.BoosterMagenta))
        )
    }
}

@Composable
private fun CapabilityPillarCard(
    icon: ImageVector,
    title: String,
    description: String,
    accent: Color,
    container: Color
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = KaaoColors.SurfaceDark),
        border = BorderStroke(1.dp, accent.copy(alpha = 0.35f))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(container),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(22.dp)
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    color = accent,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = KaaoColors.TextSecondary
                )
            }
        }
    }
}
