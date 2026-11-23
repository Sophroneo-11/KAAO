package com.kaao.security.di

import android.content.Context
import androidx.room.Room
import com.kaao.security.core.crypto.KeystorePassphraseManager
import com.kaao.security.data.local.db.CloudReputationCacheDao
import com.kaao.security.data.local.db.DnsBlockRuleDao
import com.kaao.security.data.local.db.DnsQueryLogDao
import com.kaao.security.data.local.db.GameProfileDao
import com.kaao.security.data.local.db.KaaoDatabase
import com.kaao.security.data.local.db.ScanHistoryDao
import com.kaao.security.data.local.db.ThreatSignatureDao
import com.kaao.security.data.local.db.WhitelistDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideKaaoDatabase(
        @ApplicationContext context: Context,
        passphraseManager: KeystorePassphraseManager
    ): KaaoDatabase {
        System.loadLibrary("sqlcipher")
        val passphrase = passphraseManager.getOrCreateDatabasePassphrase()
        val factory = SupportOpenHelperFactory(passphrase)
        return Room.databaseBuilder(
            context,
            KaaoDatabase::class.java,
            KaaoDatabase.DATABASE_NAME
        )
            .openHelperFactory(factory)
            .fallbackToDestructiveMigration(dropAllTables = true)
            .build()
    }

    @Provides
    fun provideThreatSignatureDao(db: KaaoDatabase): ThreatSignatureDao = db.threatSignatureDao()

    @Provides
    fun provideScanHistoryDao(db: KaaoDatabase): ScanHistoryDao = db.scanHistoryDao()

    @Provides
    fun provideWhitelistDao(db: KaaoDatabase): WhitelistDao = db.whitelistDao()

    @Provides
    fun provideDnsBlockRuleDao(db: KaaoDatabase): DnsBlockRuleDao = db.dnsBlockRuleDao()

    @Provides
    fun provideDnsQueryLogDao(db: KaaoDatabase): DnsQueryLogDao = db.dnsQueryLogDao()

    @Provides
    fun provideCloudReputationCacheDao(db: KaaoDatabase): CloudReputationCacheDao = db.cloudReputationCacheDao()

    @Provides
    fun provideGameProfileDao(db: KaaoDatabase): GameProfileDao = db.gameProfileDao()
}
