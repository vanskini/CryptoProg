#include <iostream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Использование: " << argv[0] << " <файл>\n";
        return 1;
    }

    try {
        CryptoPP::SHA256 hash;
        std::string result;

        CryptoPP::FileSource f(argv[1], true, // файл
            new CryptoPP::HashFilter(hash, // считаем хэш
                new CryptoPP::HexEncoder( // переводим в hex
                    new CryptoPP::StringSink(result) // кладём в строку
                )
            )
        );

        std::cout << result << std::endl;
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
