/* 
 * Copyright (c) 2016 - 2017 cooky451
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

#include "keccak/keccak.hpp"

#include <cstdint>

#include <array>
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <string>
#include <type_traits>

using seconds_f32 = std::chrono::duration<float, std::ratio<1, 1>>;
using seconds_f64 = std::chrono::duration<double, std::ratio<1, 1>>;
using milliseconds_f32 = std::chrono::duration<float, std::milli>;
using milliseconds_f64 = std::chrono::duration<double, std::milli>;

struct hexdump
{
	const void* data;
	std::size_t size;
};

static std::ostream& operator << (std::ostream& lhs, hexdump rhs)
{
	const std::uint8_t* p = static_cast<const std::uint8_t*>(rhs.data);
	std::size_t size = rhs.size;

	auto old_fill = lhs.fill('0');

	for (; size--; ++p)
	{
		lhs << std::hex << std::setw(2) << static_cast<unsigned>(*p);
	}

	lhs.fill(old_fill);

	return lhs;
}

template <typename F>
static void bench_function(const std::string& description, std::size_t buffer_size, F&& func)
{
	using namespace std::chrono;

	std::cout << description;

	auto start_time = steady_clock::now();
	auto buffer = func();
	auto elapsed = seconds_f64(steady_clock::now() - start_time);
	auto bandwidth = buffer_size / (1024.0 * 1024.0) / elapsed.count();

	std::cout << std::round(milliseconds_f64(elapsed).count()) << " ms\t\t";
	std::cout << std::round(bandwidth) << " MiB/s\t\t";
	std::cout << hexdump{ buffer.data(), 8 } << "\n";
}

static void benchmark(std::size_t buffer_size)
{
	std::cout << "Name\t\t\t\tTime\t\tBandwidth\t\tHex\n\n";

	std::string msg(buffer_size, 0x77);

	bench_function("SHA3-256\t\t\t", buffer_size, [&] {
		return keccak::sha3_256_hasher(msg.data(), msg.size()).finish();
	});

	bench_function("SHA3-512\t\t\t", buffer_size, [&] {
		return keccak::sha3_512_hasher(msg.data(), msg.size()).finish();
	});

	bench_function("SHAKE128\t\t\t", buffer_size, [&] {
		return keccak::shake128_hasher(msg.data(), msg.size()).finish();
	});

	bench_function("SHAKE256\t\t\t", buffer_size, [&] {
		return keccak::shake256_hasher(msg.data(), msg.size()).finish();
	});

	std::string buf(buffer_size, char{});

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

	std::uniform_int_distribution<decltype(min)> d(min, max);
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
