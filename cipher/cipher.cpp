#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cryptopp/aes.h>
#include <cryptopp/camellia.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

using namespace CryptoPP;

const int SALT_LEN = 16;
const int ITER = 10000;

// Генерация ключа из пароля (через PBKDF)
std::vector<byte> makeKey(const std::string& pass, const byte* salt, size_t keyLen) {
    std::vector<byte> key(keyLen);
    PKCS12_PBKDF<SHA256> pbkdf;
    
    // ВАЖНО: в конце добавлен 0.0 — это обязательный аргумент для новых версий Crypto++
    pbkdf.DeriveKey(key.data(), key.size(), 0,
                    (const byte*)pass.data(), pass.size(),
                    salt, SALT_LEN, ITER, 0.0);
    return key;
}

// Шаблонная функция для шифрования/расшифрования
template <class CIPHER>
void doCrypt(bool enc, const std::string& inName, const std::string& outName, const std::string& pass) {
    const int IV_LEN = CIPHER::BLOCKSIZE; 
    std::vector<byte> salt(SALT_LEN), iv(IV_LEN);

    if (enc) {
        AutoSeededRandomPool rng;
        rng.GenerateBlock(salt.data(), salt.size());
        rng.GenerateBlock(iv.data(), iv.size());

        auto key = makeKey(pass, salt.data(), CIPHER::DEFAULT_KEYLENGTH);

        // Обязательно typename перед CBC_Mode
        typename CBC_Mode<CIPHER>::Encryption enc2;
        enc2.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        std::ifstream in(inName, std::ios::binary);
        std::ofstream out(outName, std::ios::binary);
        if (!in || !out) throw std::runtime_error("Ошибка открытия файла");

        out.write((char*)salt.data(), salt.size());
        out.write((char*)iv.data(), iv.size());

        FileSource fs(in, true, new StreamTransformationFilter(enc2, new FileSink(out)));
        std::cout << "Файл успешно зашифрован.\n";
    } else {
        std::ifstream in(inName, std::ios::binary);
        std::ofstream out(outName, std::ios::binary);
        if (!in || !out) throw std::runtime_error("Ошибка открытия файла");

        in.read((char*)salt.data(), salt.size());
        in.read((char*)iv.data(), iv.size());

        auto key = makeKey(pass, salt.data(), CIPHER::DEFAULT_KEYLENGTH);

        // Обязательно typename перед CBC_Mode
        typename CBC_Mode<CIPHER>::Decryption dec2;
        dec2.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        FileSource fs(in, true, new StreamTransformationFilter(dec2, new FileSink(out)));
        std::cout << "Файл успешно расшифрован.\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cout << "Использование: " << argv[0] 
                  << " <enc|dec> <AES|Camellia> <входной_файл> <выходной_файл> <пароль>\n";
        return 1;
    }

    std::string op   = argv[1];
    std::string alg  = argv[2];
    std::string in   = argv[3];
    std::string out  = argv[4];
    std::string pass = argv[5];

    if (op != "enc" && op != "dec") {
        std::cerr << "Ошибка: операция должна быть 'enc' или 'dec'\n";
        return 1;
    }
    bool enc = (op == "enc");

    try {
        if (alg == "AES") {
            doCrypt<AES>(enc, in, out, pass);
        } else if (alg == "Camellia") {
            doCrypt<Camellia>(enc, in, out, pass);
        } else {
            std::cerr << "Ошибка: алгоритм должен быть 'AES' или 'Camellia'\n";
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
