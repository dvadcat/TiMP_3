#include <UnitTest++/UnitTest++.h>
#include <Cipher.h>
#include <iostream>
#include <locale>
#include <codecvt>
using namespace std;
struct KeyB_fixture {
    Cipher * p;
    KeyB_fixture()
    {
        p = new Cipher(L"4");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};
wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("С-У-РЬГТ", codec.to_bytes(Cipher(L"4").encrypt(L"ГРУСТЬ")));
    }
    TEST(LongKey) {
        CHECK_EQUAL("ЬТСУРГ",codec.to_bytes(Cipher(L"6").encrypt(L"ГРУСТЬ")));
    }
    TEST(NegativeKey) {
        CHECK_THROW(Cipher cp(L"-5"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(Cipher cp(L"2 2"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(Cipher cp(L""),cipher_error);
    }
    TEST(AlphaAndPunctuationInKey) {
        CHECK_THROW(Cipher cp(L"МАМ!!"),cipher_error);
    }
}
SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("С-У-РЬГТ",
                    codec.to_bytes(p->encrypt(L"ГРУСТЬ")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("С-У-РЬГТ",
                    codec.to_bytes(p->encrypt(L"грусть")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("С-У-РЬГТ",
                    codec.to_bytes(p->encrypt(L"Г!РУ С Т,Ь")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("С-У-РЬГТ", codec.to_bytes(p->encrypt(L"ГР11У3СТ1Ь")));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"123+8764=9999"),cipher_error);
    }
}
SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ГРУСТЬ",
                    codec.to_bytes(p->decrypt(L"С-У-РЬГТ")));
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"С -У-РЬГТ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"С-У-54РЬГТ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt(L"С,-У-РЬ,ГТ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""),cipher_error);
    }
}
int main(int argc, char **argv)
{
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    return UnitTest::RunAllTests();
}