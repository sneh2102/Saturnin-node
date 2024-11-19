#include <napi.h>
#include "saturnin.h"
#include "internal-saturnin.h"
#include <vector>
#include <cstring>

class SaturninWrapper : public Napi::ObjectWrap<SaturninWrapper> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    SaturninWrapper(const Napi::CallbackInfo& info);

private:
    static Napi::FunctionReference constructor;
    Napi::Value Encrypt(const Napi::CallbackInfo& info);
    Napi::Value Decrypt(const Napi::CallbackInfo& info);
    Napi::Value Hash(const Napi::CallbackInfo& info);
    Napi::Value ShortEncrypt(const Napi::CallbackInfo& info);
    Napi::Value ShortDecrypt(const Napi::CallbackInfo& info);
};

Napi::FunctionReference SaturninWrapper::constructor;

SaturninWrapper::SaturninWrapper(const Napi::CallbackInfo& info) 
    : Napi::ObjectWrap<SaturninWrapper>(info) {}

Napi::Object SaturninWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);

    Napi::Function func = DefineClass(env, "Saturnin", {
        InstanceMethod("encrypt", &SaturninWrapper::Encrypt),
        InstanceMethod("decrypt", &SaturninWrapper::Decrypt),
        InstanceMethod("hash", &SaturninWrapper::Hash),
        InstanceMethod("shortEncrypt", &SaturninWrapper::ShortEncrypt),
        InstanceMethod("shortDecrypt", &SaturninWrapper::ShortDecrypt),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    exports.Set("Saturnin", func);
    exports.Set("KEY_SIZE", Napi::Number::New(env, SATURNIN_KEY_SIZE));
    exports.Set("NONCE_SIZE", Napi::Number::New(env, SATURNIN_NONCE_SIZE));
    exports.Set("TAG_SIZE", Napi::Number::New(env, SATURNIN_TAG_SIZE));
    exports.Set("HASH_SIZE", Napi::Number::New(env, SATURNIN_HASH_SIZE));

    return exports;
}

Napi::Value SaturninWrapper::Encrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 4) {
        throw Napi::Error::New(env, "Wrong number of arguments");
    }

    if (!info[0].IsBuffer() || !info[1].IsBuffer() || 
        !info[2].IsBuffer() || !info[3].IsBuffer()) {
        throw Napi::Error::New(env, "Wrong argument types");
    }

    auto message = info[0].As<Napi::Buffer<uint8_t>>();
    auto ad = info[1].As<Napi::Buffer<uint8_t>>();
    auto nonce = info[2].As<Napi::Buffer<uint8_t>>();
    auto key = info[3].As<Napi::Buffer<uint8_t>>();

    if (nonce.Length() != SATURNIN_NONCE_SIZE) {
        throw Napi::Error::New(env, "Invalid nonce length");
    }
    if (key.Length() != SATURNIN_KEY_SIZE) {
        throw Napi::Error::New(env, "Invalid key length");
    }

    unsigned long long clen;
    auto ciphertext = Napi::Buffer<uint8_t>::New(
        env, message.Length() + SATURNIN_TAG_SIZE);

    int result = saturnin_aead_encrypt(
        ciphertext.Data(), &clen,
        message.Data(), message.Length(),
        ad.Data(), ad.Length(),
        nullptr,
        nonce.Data(),
        key.Data()
    );

    if (result != 0) {
        throw Napi::Error::New(env, "Encryption failed");
    }

    return ciphertext;
}

Napi::Value SaturninWrapper::Decrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 4) {
        throw Napi::Error::New(env, "Wrong number of arguments");
    }

    if (!info[0].IsBuffer() || !info[1].IsBuffer() || 
        !info[2].IsBuffer() || !info[3].IsBuffer()) {
        throw Napi::Error::New(env, "Wrong argument types");
    }

    auto ciphertext = info[0].As<Napi::Buffer<uint8_t>>();
    auto ad = info[1].As<Napi::Buffer<uint8_t>>();
    auto nonce = info[2].As<Napi::Buffer<uint8_t>>();
    auto key = info[3].As<Napi::Buffer<uint8_t>>();

    if (ciphertext.Length() < SATURNIN_TAG_SIZE) {
        throw Napi::Error::New(env, "Invalid ciphertext length");
    }
    if (nonce.Length() != SATURNIN_NONCE_SIZE) {
        throw Napi::Error::New(env, "Invalid nonce length");
    }
    if (key.Length() != SATURNIN_KEY_SIZE) {
        throw Napi::Error::New(env, "Invalid key length");
    }

    unsigned long long mlen;
    auto message = Napi::Buffer<uint8_t>::New(
        env, ciphertext.Length() - SATURNIN_TAG_SIZE);

    int result = saturnin_aead_decrypt(
        message.Data(), &mlen,
        nullptr,
        ciphertext.Data(), ciphertext.Length(),
        ad.Data(), ad.Length(),
        nonce.Data(),
        key.Data()
    );

    if (result != 0) {
        throw Napi::Error::New(env, "Decryption failed or authentication failed");
    }

    return message;
}

Napi::Value SaturninWrapper::Hash(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1) {
        throw Napi::Error::New(env, "Wrong number of arguments");
    }

    if (!info[0].IsBuffer()) {
        throw Napi::Error::New(env, "Wrong argument type");
    }

    auto message = info[0].As<Napi::Buffer<uint8_t>>();
    auto hash = Napi::Buffer<uint8_t>::New(env, SATURNIN_HASH_SIZE);

    int result = saturnin_hash(
        hash.Data(),
        message.Data(),
        message.Length()
    );

    if (result != 0) {
        throw Napi::Error::New(env, "Hashing failed");
    }

    return hash;
}

Napi::Value SaturninWrapper::ShortEncrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 4) {
        throw Napi::Error::New(env, "Wrong number of arguments");
    }

    if (!info[0].IsBuffer() || !info[1].IsBuffer() || 
        !info[2].IsBuffer() || !info[3].IsBuffer()) {
        throw Napi::Error::New(env, "Wrong argument types");
    }

    auto message = info[0].As<Napi::Buffer<uint8_t>>();
    auto ad = info[1].As<Napi::Buffer<uint8_t>>();
    auto nonce = info[2].As<Napi::Buffer<uint8_t>>();
    auto key = info[3].As<Napi::Buffer<uint8_t>>();

    if (message.Length() > 15) {
        throw Napi::Error::New(env, "Message too long for short AEAD");
    }
    if (nonce.Length() != SATURNIN_NONCE_SIZE) {
        throw Napi::Error::New(env, "Invalid nonce length");
    }
    if (key.Length() != SATURNIN_KEY_SIZE) {
        throw Napi::Error::New(env, "Invalid key length");
    }

    unsigned long long clen;
    auto ciphertext = Napi::Buffer<uint8_t>::New(env, 32);

    int result = saturnin_short_aead_encrypt(
        ciphertext.Data(), &clen,
        message.Data(), message.Length(),
        ad.Data(), ad.Length(),
        nullptr,
        nonce.Data(),
        key.Data()
    );

    if (result != 0) {
        throw Napi::Error::New(env, "Short encryption failed");
    }

    return ciphertext;
}

Napi::Value SaturninWrapper::ShortDecrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 4) {
        throw Napi::Error::New(env, "Wrong number of arguments");
    }

    if (!info[0].IsBuffer() || !info[1].IsBuffer() || 
        !info[2].IsBuffer() || !info[3].IsBuffer()) {
        throw Napi::Error::New(env, "Wrong argument types");
    }

    auto ciphertext = info[0].As<Napi::Buffer<uint8_t>>();
    auto ad = info[1].As<Napi::Buffer<uint8_t>>();
    auto nonce = info[2].As<Napi::Buffer<uint8_t>>();
    auto key = info[3].As<Napi::Buffer<uint8_t>>();

    if (ciphertext.Length() != 32) {
        throw Napi::Error::New(env, "Invalid ciphertext length for short AEAD");
    }
    if (nonce.Length() != SATURNIN_NONCE_SIZE) {
        throw Napi::Error::New(env, "Invalid nonce length");
    }
    if (key.Length() != SATURNIN_KEY_SIZE) {
        throw Napi::Error::New(env, "Invalid key length");
    }

    unsigned long long mlen;
    auto message = Napi::Buffer<uint8_t>::New(env, 15); // Max size for short messages

    int result = saturnin_short_aead_decrypt(
        message.Data(), &mlen,
        nullptr,
        ciphertext.Data(), ciphertext.Length(),
        ad.Data(), ad.Length(),
        nonce.Data(),
        key.Data()
    );

    if (result != 0) {
        throw Napi::Error::New(env, "Short decryption failed or authentication failed");
    }

    // Create a new buffer with the actual message length
    auto final_message = Napi::Buffer<uint8_t>::Copy(env, message.Data(), mlen);
    return final_message;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    return SaturninWrapper::Init(env, exports);
}

NODE_API_MODULE(saturnin, Init)