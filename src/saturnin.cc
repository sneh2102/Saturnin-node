// binding.cc
#include <node.h>
#include <node_buffer.h>
#include "internal-saturnin.h"

namespace saturnin_wrapper {

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Value;
using v8::Number;
using v8::Exception;

void SetupKey(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // Check arguments
    if (args.Length() < 1 || !node::Buffer::HasInstance(args[0])) {
        isolate->ThrowException(Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong arguments").ToLocalChecked()));
        return;
    }

    // Get key buffer
    Local<Object> key_buffer = args[0].As<Object>();
    unsigned char* key_data = (unsigned char*)node::Buffer::Data(key_buffer);
    
    // Create key schedule
    saturnin_key_schedule_t* ks = new saturnin_key_schedule_t();
    saturnin_setup_key(ks, key_data);

    // Wrap the key schedule in a buffer and return it
    args.GetReturnValue().Set(node::Buffer::Copy(
        isolate,
        reinterpret_cast<char*>(ks),
        sizeof(saturnin_key_schedule_t)).ToLocalChecked());

    delete ks;
}

void EncryptBlock(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // Check arguments
    if (args.Length() < 3 || !node::Buffer::HasInstance(args[0]) ||
        !node::Buffer::HasInstance(args[1]) || !args[2]->IsNumber()) {
        isolate->ThrowException(Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong arguments").ToLocalChecked()));
        return;
    }

    // Get key schedule
    Local<Object> ks_buffer = args[0].As<Object>();
    saturnin_key_schedule_t* ks = reinterpret_cast<saturnin_key_schedule_t*>(
        node::Buffer::Data(ks_buffer));

    // Get input buffer
    Local<Object> input_buffer = args[1].As<Object>();
    unsigned char* input = (unsigned char*)node::Buffer::Data(input_buffer);

    // Get domain
    unsigned domain = args[2].As<Number>()->Value();

    // Create output buffer
    unsigned char* output = new unsigned char[32];
    
    // Encrypt
    saturnin_encrypt_block(ks, output, input, domain);

    // Return output buffer
    args.GetReturnValue().Set(node::Buffer::Copy(
        isolate,
        reinterpret_cast<char*>(output),
        32).ToLocalChecked());

    delete[] output;
}

void DecryptBlock(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // Check arguments
    if (args.Length() < 3 || !node::Buffer::HasInstance(args[0]) ||
        !node::Buffer::HasInstance(args[1]) || !args[2]->IsNumber()) {
        isolate->ThrowException(Exception::TypeError(
            v8::String::NewFromUtf8(isolate, "Wrong arguments").ToLocalChecked()));
        return;
    }

    // Get key schedule
    Local<Object> ks_buffer = args[0].As<Object>();
    saturnin_key_schedule_t* ks = reinterpret_cast<saturnin_key_schedule_t*>(
        node::Buffer::Data(ks_buffer));

    // Get input buffer
    Local<Object> input_buffer = args[1].As<Object>();
    unsigned char* input = (unsigned char*)node::Buffer::Data(input_buffer);

    // Get domain
    unsigned domain = args[2].As<Number>()->Value();

    // Create output buffer
    unsigned char* output = new unsigned char[32];
    
    // Decrypt
    saturnin_decrypt_block(ks, output, input, domain);

    // Return output buffer
    args.GetReturnValue().Set(node::Buffer::Copy(
        isolate,
        reinterpret_cast<char*>(output),
        32).ToLocalChecked());

    delete[] output;
}

void Initialize(Local<Object> exports) {
    NODE_SET_METHOD(exports, "setupKey", SetupKey);
    NODE_SET_METHOD(exports, "encryptBlock", EncryptBlock);
    NODE_SET_METHOD(exports, "decryptBlock", DecryptBlock);
}

NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)

}  // namespace saturnin_wrapper