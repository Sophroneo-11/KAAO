package com.kaao.security.data.remote

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import retrofit2.http.Field
import retrofit2.http.FormUrlEncoded
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Path

@Serializable
data class MalwareBazaarResponse(
    @SerialName("query_status") val queryStatus: String = "",
    val data: List<MalwareBazaarEntry> = emptyList()
)

@Serializable
data class MalwareBazaarEntry(
    @SerialName("sha256_hash") val sha256Hash: String = "",
    val signature: String? = null,
    @SerialName("file_type") val fileType: String? = null,
    val tags: List<String>? = null
)

interface MalwareBazaarApi {
    @FormUrlEncoded
    @POST("api/v1/")
    suspend fun queryHash(
        @Field("query") query: String = "get_info",
        @Field("hash") sha256Hash: String
    ): MalwareBazaarResponse
}

@Serializable
data class VirusTotalFileResponse(
    val data: VirusTotalData? = null
)

@Serializable
data class VirusTotalData(
    val attributes: VirusTotalAttributes? = null
)

@Serializable
data class VirusTotalAttributes(
    @SerialName("last_analysis_stats") val lastAnalysisStats: VirusTotalStats? = null,
    @SerialName("popular_threat_classification") val threatClassification: VirusTotalClassification? = null
)

@Serializable
data class VirusTotalStats(
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val harmless: Int = 0,
    val undetected: Int = 0
)

@Serializable
data class VirusTotalClassification(
    @SerialName("suggested_threat_label") val suggestedThreatLabel: String? = null
)

interface VirusTotalApi {
    @GET("api/v3/files/{sha256}")
    suspend fun getFileReport(
        @Path("sha256") sha256: String,
        @Header("x-apikey") apiKey: String
    ): VirusTotalFileResponse
}
