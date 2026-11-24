package com.kaao.security.ui.components

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.kaao.security.domain.model.HealthScoreComponent
import com.kaao.security.domain.model.ThreatSeverity
import com.kaao.security.ui.theme.KaaoColors
import com.kaao.security.ui.theme.accentColor
import com.kaao.security.ui.theme.containerColor
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun SecurityCard(
    modifier: Modifier = Modifier,
    borderColor: Color = KaaoColors.SurfaceBorder,
    containerColor: Color = KaaoColors.SurfaceDark,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        border = BorderStroke(1.dp, borderColor)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            content = content
        )
    }
}

@Composable
fun CyberGradientButton(
    text: String,
    onClick: () -> Unit,
    brush: Brush = KaaoColors.PrimaryActionGradient,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    isLoading: Boolean = false,
    contentColor: Color = KaaoColors.ObsidianBg
) {
    val shape = RoundedCornerShape(14.dp)
    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(50.dp)
            .clip(shape)
            .background(brush)
            .alpha(if (enabled && !isLoading) 1f else 0.55f)
            .clickable(enabled = enabled && !isLoading, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(18.dp),
                    strokeWidth = 2.dp,
                    color = contentColor
                )
                Spacer(modifier = Modifier.width(10.dp))
            } else if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = contentColor,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text(
                text = text,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = contentColor
            )
        }
    }
}

@Composable
fun SeverityPill(
    label: String,
    severity: ThreatSeverity,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(severity.containerColor())
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(
            text = label.uppercase(),
            style = MaterialTheme.typography.labelSmall,
            color = severity.accentColor(),
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun StatusTag(
    label: String,
    accent: Color,
    background: Color = accent.copy(alpha = 0.16f),
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(background)
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = accent,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun HealthScoreGauge(
    score: Int,
    gradeLabel: String,
    severity: ThreatSeverity,
    modifier: Modifier = Modifier,
    size: Dp = 196.dp
) {
    val animatedProgress by animateFloatAsState(
        targetValue = (score.coerceIn(0, 100) / 100f),
        animationSpec = tween(durationMillis = 900, easing = FastOutSlowInEasing),
        label = "health_score_arc"
    )
    val pulseTransition = rememberInfiniteTransition(label = "gauge_glow")
    val glowAlpha by pulseTransition.animateFloat(
        initialValue = 0.16f,
        targetValue = 0.34f,
        animationSpec = infiniteRepeatable(
            animation = tween(1800, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "gauge_glow_alpha"
    )
    val accent = severity.accentColor()
    val secondaryAccent = when (severity) {
        ThreatSeverity.SAFE -> KaaoColors.ShieldCyan
        ThreatSeverity.LOW -> KaaoColors.CleanerCobalt
        ThreatSeverity.MEDIUM -> KaaoColors.WarningAmber
        ThreatSeverity.HIGH -> KaaoColors.BoosterMagenta
        ThreatSeverity.CRITICAL -> KaaoColors.ThreatCrimson
    }

    Box(
        modifier = modifier.size(size),
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.size(size)) {
            val strokePx = 15.dp.toPx()
            val glowStrokePx = 28.dp.toPx()
            val inset = glowStrokePx / 2f
            val arcSize = Size(this.size.width - glowStrokePx, this.size.height - glowStrokePx)
            val topLeft = Offset(inset, inset)
            val center = Offset(this.size.width / 2f, this.size.height / 2f)

            // Subtle ambient radial halo behind gauge
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(accent.copy(alpha = glowAlpha), Color.Transparent),
                    center = center,
                    radius = this.size.minDimension * 0.52f
                ),
                radius = this.size.minDimension * 0.52f,
                center = center
            )

            // Outer faint track arc
            drawArc(
                color = KaaoColors.SurfaceElevated,
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = strokePx, cap = StrokeCap.Round)
            )

            val sweepAngle = 270f * animatedProgress

            // Glowing outer aura along active arc
            if (sweepAngle > 1f) {
                drawArc(
                    color = accent.copy(alpha = glowAlpha * 0.85f),
                    startAngle = 135f,
                    sweepAngle = sweepAngle,
                    useCenter = false,
                    topLeft = topLeft,
                    size = arcSize,
                    style = Stroke(width = glowStrokePx * 0.8f, cap = StrokeCap.Round)
                )

                // Vivid gradient progress arc
                drawArc(
                    brush = Brush.sweepGradient(
                        colors = listOf(secondaryAccent, accent, KaaoColors.CyberEmerald, secondaryAccent)
                    ),
                    startAngle = 135f,
                    sweepAngle = sweepAngle,
                    useCenter = false,
                    topLeft = topLeft,
                    size = arcSize,
                    style = Stroke(width = strokePx, cap = StrokeCap.Round)
                )

                // Bright beacon dot at arc tip
                val tipRad = ((135f + sweepAngle) * PI / 180.0)
                val radius = arcSize.width / 2f
                val tipX = center.x + (radius * cos(tipRad)).toFloat()
                val tipY = center.y + (radius * sin(tipRad)).toFloat()
                drawCircle(
                    color = Color.White,
                    radius = 5.dp.toPx(),
                    center = Offset(tipX, tipY)
                )
            }
        }

        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = score.toString(),
                style = MaterialTheme.typography.displaySmall,
                color = KaaoColors.TextPrimary
            )
            Text(
                text = "/ 100",
                style = MaterialTheme.typography.labelMedium,
                color = KaaoColors.TextMuted
            )
            Spacer(modifier = Modifier.height(6.dp))
            SeverityPill(label = gradeLabel, severity = severity)
        }
    }
}

@Composable
fun ScoreComponentRow(component: HealthScoreComponent) {
    val progress = (component.earnedPoints.toFloat() / component.maxPoints.coerceAtLeast(1).toFloat())
        .coerceIn(0f, 1f)
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = component.title,
                style = MaterialTheme.typography.bodyMedium,
                color = KaaoColors.TextPrimary,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = "${component.earnedPoints}/${component.maxPoints} pts",
                style = MaterialTheme.typography.labelMedium,
                color = component.severity.accentColor()
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(RoundedCornerShape(4.dp)),
            color = component.severity.accentColor(),
            trackColor = KaaoColors.SurfaceElevated
        )
        Spacer(modifier = Modifier.height(3.dp))
        Text(
            text = component.statusDetail,
            style = MaterialTheme.typography.bodySmall,
            color = KaaoColors.TextSecondary
        )
    }
}

@Composable
fun PermissionRationaleBanner(
    title: String,
    description: String,
    actionLabel: String,
    onAction: () -> Unit,
    modifier: Modifier = Modifier
) {
    SecurityCard(
        modifier = modifier,
        borderColor = KaaoColors.WarningAmber.copy(alpha = 0.55f),
        containerColor = KaaoColors.WarningAmberContainer.copy(alpha = 0.35f)
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = KaaoColors.WarningAmber
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = description,
            style = MaterialTheme.typography.bodySmall,
            color = KaaoColors.TextPrimary
        )
        Spacer(modifier = Modifier.height(10.dp))
        OutlinedButton(
            onClick = onAction,
            border = BorderStroke(1.dp, KaaoColors.WarningAmber),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = KaaoColors.WarningAmber)
        ) {
            Text(text = actionLabel)
        }
    }
}

@Composable
fun SectionHeader(
    title: String,
    trailingText: String? = null,
    accentColor: Color = KaaoColors.TextSecondary,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = KaaoColors.TextPrimary
        )
        if (!trailingText.isNullOrBlank()) {
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = trailingText,
                style = MaterialTheme.typography.labelMedium,
                color = accentColor
            )
        }
    }
}
