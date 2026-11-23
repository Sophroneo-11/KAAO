package com.kaao.security.data.remote

import com.kaao.security.core.crypto.SignedDefinitionBundle
import retrofit2.http.GET
import retrofit2.http.Url

interface DefinitionFeedApi {
    @GET
    suspend fun fetchSignedBundle(@Url feedUrl: String): SignedDefinitionBundle
}
