package com.kaao.security.engine.network

import android.net.VpnService
import com.kaao.security.domain.model.DohProvider
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import javax.net.SocketFactory

/**
 * RFC 8484 Binary DNS-over-HTTPS (application/dns-message) resolver.
 * Uses a VpnService.protect()-backed SocketFactory so upstream DoH queries bypass the local TUN interface.
 */
@Singleton
class DohClient @Inject constructor(
    private val certificatePinner: CertificatePinner
) {
    private val dnsMessageMediaType = "application/dns-message".toMediaType()

    fun createProtectedClient(vpnService: VpnService): OkHttpClient {
        val protectedSocketFactory = object : SocketFactory() {
            private val delegate = getDefault()

            override fun createSocket(): Socket =
                delegate.createSocket().also { vpnService.protect(it) }

            override fun createSocket(host: String, port: Int): Socket =
                delegate.createSocket(host, port).also { vpnService.protect(it) }

            override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
                delegate.createSocket(host, port, localHost, localPort).also { vpnService.protect(it) }

            override fun createSocket(host: InetAddress, port: Int): Socket =
                delegate.createSocket(host, port).also { vpnService.protect(it) }

            override fun createSocket(
                address: InetAddress,
                port: Int,
                localAddress: InetAddress,
                localPort: Int
            ): Socket = delegate.createSocket(address, port, localAddress, localPort).also { vpnService.protect(it) }
        }

        return OkHttpClient.Builder()
            .socketFactory(protectedSocketFactory)
            .certificatePinner(certificatePinner)
            .connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(4, TimeUnit.SECONDS)
            .writeTimeout(4, TimeUnit.SECONDS)
            .build()
    }

    fun resolveWireQuery(
        client: OkHttpClient,
        provider: DohProvider,
        dnsWireQuery: ByteArray
    ): ByteArray? = runCatching {
        val request = Request.Builder()
            .url(provider.endpointUrl)
            .header("Accept", "application/dns-message")
            .post(dnsWireQuery.toRequestBody(dnsMessageMediaType))
            .build()
        client.newCall(request).execute().use { response ->
            if (response.isSuccessful) {
                response.body?.bytes()
            } else {
                null
            }
        }
    }.getOrNull()
}
