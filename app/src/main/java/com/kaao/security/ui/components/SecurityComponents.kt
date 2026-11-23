package com.kaao.security.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
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
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.kaao.security.domain.model.HealthScoreComponent
import com.kaao.security.domain.model.ThreatSeverity
import com.kaao.security.ui.theme.KaaoColors
import com.kaao.security.ui.theme.accentColor
import com.kaao.security.ui.theme.containerColor

@Composable
fun SecurityCard(
    modifier: Modifier = Modifier,
    borderColor: Color = KaaoColors.SurfaceBorder,
    containerColor: Color = KaaoColors.SurfaceDark,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
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
    background: Color = accent.copy(alpha = 0.14f),
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
    size: Dp = 176.dp
) {
    val animatedProgress by animateFloatAsState(
        targetValue = (score.coerceIn(0, 100) / 100f),
        animationSpec = tween(durationMillis = 850),
        label = "health_score_arc"
    )
    val accent = severity.accentColor()

    Box(
        modifier = modifier.size(size),
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.size(size)) {
            val strokePx = 14.dp.toPx()
            val inset = strokePx / 2f
            val arcSize = Size(this.size.width - strokePx, this.size.height - strokePx)
            val topLeft = Offset(inset, inset)

            // Track arc
            drawArc(
                color = KaaoColors.SurfaceElevated,
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = strokePx, cap = StrokeCap.Round)
            )

            // Progress arc
            drawArc(
                brush = Brush.sweepGradient(
                    listOf(KaaoColors.ShieldCyan, accent, accent)
                ),
                startAngle = 135f,
                sweepAngle = 270f * animatedProgress,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = strokePx, cap = StrokeCap.Round)
            )
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
        borderColor = KaaoColors.WarningAmber.copy(alpha = 0.5f),
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
                color = KaaoColors.TextSecondary
            )
        }
    }
}
