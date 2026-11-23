# KAAO ProGuard / R8 hardening rules
-keepattributes *Annotation*, Signature, InnerClasses, EnclosingMethod, SourceFile, LineNumberTable

# SQLCipher 4.6.1
-keep class net.zetetic.** { *; }
-keep class net.sqlcipher.** { *; }

# Kotlinx Serialization
-keepattributes RuntimeVisibleAnnotations, AnnotationDefault
-dontwarn kotlinx.serialization.json.**
-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.kaao.security.**$$serializer { *; }
-keepclassmembers class com.kaao.security.** {
    *** Companion;
}
-keepclasseswithmembers class com.kaao.security.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Retrofit & OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**
-keep class com.kaao.security.data.remote.** { *; }
