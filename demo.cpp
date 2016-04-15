
#include "keccak/keccak.hpp"

#include <cstdint>

#include <array>
#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <random>
#include <string>
#include <type_traits>

template <typename T, typename Rep, typename Period>
static T float_duration(const std::chrono::duration<Rep, Period>& duration, T mul = T(1))
{
	return duration.count() * mul * (T(Period::num) / T(Period::den));
	static_assert(std::is_floating_point<T>::value, "Can only cast to floating point types.");
}

struct hexdump
{
	const void* data;
	std::size_t size;
};

static std::ostream& operator << (std::ostream& lhs, hexdump rhs)
{
	static const char table[256][3] =
	{
		"00", "01", "02", "03", "04", "05", "06", "07",
		"08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
		"10", "11", "12", "13", "14", "15", "16", "17",
		"18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
		"20", "21", "22", "23", "24", "25", "26", "27",
		"28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
		"30", "31", "32", "33", "34", "35", "36", "37",
		"38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
		"40", "41", "42", "43", "44", "45", "46", "47",
		"48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
		"50", "51", "52", "53", "54", "55", "56", "57",
		"58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
		"60", "61", "62", "63", "64", "65", "66", "67",
		"68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
		"70", "71", "72", "73", "74", "75", "76", "77",
		"78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
		"80", "81", "82", "83", "84", "85", "86", "87",
		"88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
		"90", "91", "92", "93", "94", "95", "96", "97",
		"98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
		"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
		"a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
		"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
		"b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
		"c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
		"c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
		"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
		"d8", "d9", "da", "db", "dc", "dd", "de", "df",
		"e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7",
		"e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
		"f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
		"f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff",
	};

	const unsigned char* p = static_cast<const unsigned char*>(rhs.data);
	std::size_t size = rhs.size;

	for (; size--; ++p)
		lhs << table[*p];

	return lhs;
}

template <typename F>
static void bench_function(const std::string& description, std::size_t buffer_size, F&& func)
{
	using namespace std::chrono;

	std::cout << description;

	auto start_time = steady_clock::now();
	auto buffer = func();
	auto elapsed = float_duration<double>(steady_clock::now() - start_time);
	auto bandwidth = buffer_size / (1024.0 * 1024.0) / elapsed;

	std::cout << std::round(elapsed * 1000.0) << " ms\t\t";
	std::cout << std::round(bandwidth) << " MiB/s\t\t";
	std::cout << hexdump{ buffer.data(), 8 } << "\n";
}

static void benchmark(std::size_t buffer_size)
{
	std::cout << "Name\t\t\t\tTime\t\tBandwidth\t\tHex\n\n";

	std::string msg(buffer_size, 0x77);

	bench_function("SHA3-256\t\t\t", buffer_size, [&] { return keccak::sha3_256_hasher(msg.data(), msg.size()).finish(); });
	bench_function("SHA3-512\t\t\t", buffer_size, [&] { return keccak::sha3_512_hasher(msg.data(), msg.size()).finish(); });
	bench_function("SHAKE128\t\t\t", buffer_size, [&] { return keccak::shake128_hasher(msg.data(), msg.size()).finish(); });
	bench_function("SHAKE256\t\t\t", buffer_size, [&] { return keccak::shake256_hasher(msg.data(), msg.size()).finish(); });

	std::string buf(buffer_size, char());

	bench_function("Auth. 128-bit encryption\t", buffer_size, [&] { 
		keccak::authenticated_encrypter_128 encrypt(msg.data(), 16);
		std::array<std::uint8_t, 16> tag;
		encrypt(nullptr, 0, &buf[0], msg.data(), msg.size(), tag.data(), tag.size());
		return tag;
	});

	bench_function("Auth. 256-bit encryption\t", buffer_size, [&] { 
		keccak::authenticated_encrypter_256 encrypt(msg.data(), 32);
		std::array<std::uint8_t, 16> tag;
		encrypt(nullptr, 0, &buf[0], msg.data(), msg.size(), tag.data(), tag.size());
		return tag;
	});

	bench_function("CSPRNG 128-bit\t\t\t", buffer_size, [&] {
		keccak::random_engine_128 rng(nullptr, 0);
		rng(&buf[0], buf.size());
		std::array<std::uint8_t, 8> tag;
		std::copy(buf.end() - 8, buf.end(), tag.begin());
		return tag;
	});

	std::cout << "\n\n";
}

static void hash()
{
	std::cout << "Enter something to hash!\n";

	std::string msg;

	while (std::cout << "# " && std::getline(std::cin, msg))
	{
		auto sha3_256_hash = keccak::sha3_256_hasher(msg.data(), msg.size()).finish();
		auto sha3_512_hash = keccak::sha3_512_hasher(msg.data(), msg.size()).finish();
		auto shake128_hash = keccak::shake128_hasher(msg.data(), msg.size()).finish();
		auto shake256_hash = keccak::shake256_hasher(msg.data(), msg.size()).finish();

		std::cout
			<< "SHA3-256:\t" << hexdump{ sha3_256_hash.data(), sha3_256_hash.size() } << "\n\n"
			<< "SHA3-512:\t" << hexdump{ sha3_512_hash.data(), 32 }
			<< "\n\t\t" << hexdump{ sha3_512_hash.data() + 32, 32 } << "\n\n";

		std::cout
			<< "SHAKE128:\t" << hexdump{ shake128_hash.data(), shake128_hash.size() } << "\n\n"
			<< "SHAKE256:\t" << hexdump{ shake256_hash.data(), 32 }
			<< "\n\t\t" << hexdump{ shake256_hash.data() + 32, 32 } << "\n\n";
	}
}

void authenticated_encryption()
{
	std::cout << "Key: ";
	std::string key;
	std::getline(std::cin, key);

	keccak::authenticated_encrypter_128 encrypt(key.data(), key.size());
	keccak::authenticated_decrypter_128 decrypt(key.data(), key.size());

	std::string msg;
	while (std::cout << "# " && std::getline(std::cin, msg))
	{
		std::string buf(msg.size(), ' ');
		std::string etag(16, ' '), dtag(16, ' ');

		encrypt(nullptr, 0, &buf[0], msg.data(), msg.size(), &etag[0], etag.size());
		msg = std::string(buf.size(), char());
		decrypt(nullptr, 0, &msg[0], buf.data(), buf.size(), &dtag[0], dtag.size());

		std::cout
			<< "Encrypted:\t" << hexdump{ buf.data(), buf.size() } << '\n'
			<< "Decrypted:\t" << msg << '\n'
			<< "Enc. Tag:\t" << hexdump{ etag.data(), etag.size() } << '\n'
			<< "Dec. Tag:\t" << hexdump{ dtag.data(), dtag.size() } << '\n';
	}
}

void random_number_generation()
{
	std::cout << "Seed: ";
	std::string seed;
	std::getline(std::cin, seed);

	std::int32_t min = 0, max = 0;

	while (std::cout << "Min/Max: " && !(std::cin >> min >> max))
	{
		std::cin.clear();
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	}

	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

	keccak::random_engine_128 rng(seed.data(), seed.size());

	do {
		std::uniform_int_distribution<std::uint32_t> d(min, max);
		std::cout << "Numbers: " << d(rng) << ' ' << d(rng) << ' ' << d(rng) << ' ' << d(rng);
	} while (std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'));
}

void random_number_test()
{
	std::cout << "Seed: ";
	std::string seed;
	std::getline(std::cin, seed);

	std::int32_t min = 0, max = 0;
	std::uint32_t iterations = 0;

	while (std::cout << "Min/Max/Iterations: " && !(std::cin >> min >> max >> iterations))
	{
		std::cin.clear();
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	}

	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

	keccak::random_engine_128 rng(seed.data(), seed.size());

	std::uniform_int_distribution<std::uint32_t> d(min, max);
	std::map<std::int32_t, std::uint32_t> m;

	while (iterations--)
	{
		m[d(rng)] += 1;
	}

	for (auto i = min; i <= max; ++i)
	{
		std::cout << i << ": " << m[i] << '\n';
	}
}

int main()
{
	try
	{
		for (;;)
		{
			std::cout
				<< "[ 0 ] Quit\n"
				<< "[ 1 ] Benchmark (256MB buffer)\n"
				<< "[ 2 ] Hash\n"
				<< "[ 3 ] Authenticated Encryption\n"
				<< "[ 4 ] Random Number Generation\n"
				<< "[ 5 ] Random Number Test\n";

			unsigned choice = 77;
			while (choice > 5)
			{
				std::cout << "# ";
				std::cin >> choice;
				std::cin.clear();
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			}

			switch (choice)
			{
			default:
				break;

			case 0:
				std::cout << "Bye~";
				return 0;

			case 1:
				benchmark(256 * 1024 * 1024);
				break;

			case 2:
				hash();
				break;

			case 3:
				authenticated_encryption();
				break;

			case 4:
				random_number_generation();
				break;

			case 5:
				random_number_test();
				break;
			}
		}
	}
	catch (std::exception& e)
	{
		std::cerr << "Fatal error: " << e.what() << '\n';
	}
	catch (...)
	{
		std::cerr << "Unknown exception occured.\n";
	}
}
