package com.kaao.security.di

import com.kaao.security.data.remote.CloudReputationProvider
import com.kaao.security.data.remote.MalwareBazaarApi
import com.kaao.security.data.remote.MalwareBazaarProvider
import com.kaao.security.data.remote.VirusTotalApi
import com.kaao.security.data.remote.VirusTotalProvider
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.IntoSet
import kotlinx.serialization.json.Json
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import java.util.concurrent.TimeUnit
import javax.inject.Named
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    /**
     * Hardened TLS CertificatePinner using primary + backup root/intermediate SPKI pins
     * (ISRG Root X1/X2, DigiCert Global Root G2/CA, Google Trust Services Root R1/R4).
     */
    @Provides
    @Singleton
    fun provideCertificatePinner(): CertificatePinner {
        val isrgRootX1 = "sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="
        val isrgRootX2 = "sha256/diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI="
        val digiCertGlobalRootCa = "sha256/r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="
        val digiCertGlobalRootG2 = "sha256/i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY="
        val gtsRootR1 = "sha256/hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc="
        val gtsRootR4 = "sha256/mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c="

        return CertificatePinner.Builder()
            .add("mb-api.abuse.ch", isrgRootX1, isrgRootX2, digiCertGlobalRootG2, gtsRootR1)
            .add("www.virustotal.com", gtsRootR1, gtsRootR4, digiCertGlobalRootG2, digiCertGlobalRootCa)
            .add("cloudflare-dns.com", digiCertGlobalRootG2, digiCertGlobalRootCa, gtsRootR1, gtsRootR4)
            .add("dns.quad9.net", digiCertGlobalRootG2, digiCertGlobalRootCa, isrgRootX1)
            .build()
    }

    @Provides
    @Singleton
    fun provideJson(): Json = Json {
        ignoreUnknownKeys = true
        isLenient = true
        coerceInputValues = true
    }

    @Provides
    @Singleton
    fun provideOkHttpClient(certificatePinner: CertificatePinner): OkHttpClient {
        return OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(12, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }

    @Provides
    @Singleton
    @Named("malwareBazaar")
    fun provideMalwareBazaarRetrofit(okHttpClient: OkHttpClient, json: Json): Retrofit {
        return Retrofit.Builder()
            .baseUrl("https://mb-api.abuse.ch/")
            .client(okHttpClient)
            .addConverterFactory(json.asConverterFactory("application/json; charset=UTF8".toMediaType()))
            .build()
    }

    @Provides
    @Singleton
    @Named("virusTotal")
    fun provideVirusTotalRetrofit(okHttpClient: OkHttpClient, json: Json): Retrofit {
        return Retrofit.Builder()
            .baseUrl("https://www.virustotal.com/")
            .client(okHttpClient)
            .addConverterFactory(json.asConverterFactory("application/json; charset=UTF8".toMediaType()))
            .build()
    }

    @Provides
    @Singleton
    fun provideMalwareBazaarApi(@Named("malwareBazaar") retrofit: Retrofit): MalwareBazaarApi =
        retrofit.create(MalwareBazaarApi::class.java)

    @Provides
    @Singleton
    fun provideVirusTotalApi(@Named("virusTotal") retrofit: Retrofit): VirusTotalApi =
        retrofit.create(VirusTotalApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class CloudReputationBindingModule {
    @Binds
    @IntoSet
    abstract fun bindMalwareBazaarProvider(impl: MalwareBazaarProvider): CloudReputationProvider

    @Binds
    @IntoSet
    abstract fun bindVirusTotalProvider(impl: VirusTotalProvider): CloudReputationProvider
}
