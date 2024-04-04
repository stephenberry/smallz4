#include "smallz4.hpp"

#include <cstdio> // stdin/stdout/stderr, fopen, ...
#include <cstdlib> // exit
#include <ctime> // time (verbose output)

#include "smallz4_original.hpp"

// This program is a shorter, more readable, albeit slower re-implementation of lz4cat (
// https://github.com/Cyan4973/xxHash )

// Limitations:
// - skippable frames and legacy frames are not implemented (and most likely never will)
// - checksums are not verified (see https://create.stephan-brumme.com/xxhash/ for a simple implementation)

#include <stdio.h> // stdin/stdout/stderr, fopen, ...
#include <stdlib.h> // exit()
#include <string.h> // memcpy

/// error handler
static void unlz4error(const char* msg)
{
   // smaller static binary than fprintf(stderr, "ERROR: %s\n", msg);
   fputs("ERROR: ", stderr);
   fputs(msg, stderr);
   fputc('\n', stderr);
   exit(1);
}

// ==================== LZ4 DECOMPRESSOR ====================

/// decompress everything in input stream (accessed via getByte) and write to output stream (via sendBytes)
void unlz4(const unsigned char*& it, const unsigned char* end, std::string& b, size_t& ix, const char* dictionary)
{
   // signature
   unsigned char signature1 = *it;
   ++it;
   unsigned char signature2 = *it;
   ++it;
   unsigned char signature3 = *it;
   ++it;
   unsigned char signature4 = *it;
   ++it;
   uint32_t signature = (signature4 << 24) | (signature3 << 16) | (signature2 << 8) | signature1;
   unsigned char isModern = (signature == 0x184D2204);
   unsigned char isLegacy = (signature == 0x184C2102);
   if (!isModern) {
      unlz4error("invalid signature");
   }

   unsigned char hasBlockChecksum = 0;
   unsigned char hasContentSize = 0;
   unsigned char hasContentChecksum = 0;
   unsigned char hasDictionaryID = 0;
   // flags
   unsigned char flags = *it;
   ++it;
   hasBlockChecksum = flags & 16;
   hasContentSize = flags & 8;
   hasContentChecksum = flags & 4;
   hasDictionaryID = flags & 1;

   // only version 1 file format
   unsigned char version = flags >> 6;
   if (version != 1) {
      unlz4error("only LZ4 file format version 1 supported");
   }

   // ignore blocksize
   char numIgnore = 1;

   if (hasContentSize) numIgnore += 8; // ignore
   if (hasDictionaryID) numIgnore += 4; // ignore

   // ignore header checksum (xxhash32 of everything up this point & 0xFF)
   ++numIgnore;

   it += numIgnore; // skip all those ignored bytes

   static constexpr size_t HISTORY_SIZE = 64 * 1024; // don't lower this value, backreferences can be 64kb far away
   unsigned char history[HISTORY_SIZE]; // contains the latest decoded data
   uint32_t pos = 0; // next free position in history[]

   // dictionary compression is a recently introduced feature, just move its contents to the buffer
   if (dictionary) {
      // open dictionary
      FILE* dict = fopen(dictionary, "rb");
      if (!dict) unlz4error("cannot open dictionary");

      // get dictionary's filesize
      fseek(dict, 0, SEEK_END);
      int64_t dictSize = ftell(dict);
      // only the last 64k are relevant
      int64_t relevant = dictSize < 65536 ? 0 : dictSize - 65536;
      fseek(dict, relevant, SEEK_SET);
      if (dictSize > 65536) dictSize = 65536;
      // read it and store it at the end of the buffer
      fread(history + HISTORY_SIZE - dictSize, 1, dictSize, dict);
      fclose(dict);
   }

   // parse all blocks until blockSize == 0
   while (true) {
      uint32_t blockSize = *it;
      ++it;
      blockSize |= uint32_t(*it) << 8;
      ++it;
      blockSize |= uint32_t(*it) << 16;
      ++it;
      blockSize |= uint32_t(*it) << 24;
      ++it;

      // highest bit set ?
      unsigned char isCompressed = (blockSize & 0x80000000) == 0;
      blockSize &= 0x7FFFFFFF;

      // stop after last block
      if (blockSize == 0) break;

      if (isCompressed) {
         // decompress block
         uint32_t blockOffset = 0;
         uint32_t numWritten = 0;
         while (blockOffset < blockSize) {
            // get a token
            unsigned char token = *it;
            ++it;
            blockOffset++;

            // determine number of literals
            uint32_t numLiterals = token >> 4;
            if (numLiterals == 15) {
               // number of literals length encoded in more than 1 byte
               unsigned char current;
               do {
                  current = *it;
                  ++it;
                  numLiterals += current;
                  blockOffset++;
               } while (current == 255);
            }

            blockOffset += numLiterals;

            // copy all those literals
            if (pos + numLiterals < HISTORY_SIZE) {
               // fast loop
               while (numLiterals-- > 0) {
                  history[pos++] = *it;
                  ++it;
               }
            }
            else {
               // slow loop
               while (numLiterals-- > 0) {
                  history[pos++] = *it;
                  ++it;

                  // flush output buffer
                  if (pos == HISTORY_SIZE) {
                     smallz4::dump({history, HISTORY_SIZE}, b, ix);
                     numWritten += HISTORY_SIZE;
                     pos = 0;
                  }
               }
            }

            // last token has only literals
            if (blockOffset == blockSize) break;

            // match distance is encoded in two bytes (little endian)
            uint32_t delta = *it;
            ++it;
            delta |= (uint32_t)(*it) << 8;
            ++it;
            // zero isn't allowed
            if (delta == 0) unlz4error("invalid offset");
            blockOffset += 2;

            // match length (always >= 4, therefore length is stored minus 4)
            uint32_t matchLength = 4 + (token & 0x0F);
            if (matchLength == 4 + 0x0F) {
               unsigned char current;
               do // match length encoded in more than 1 byte
               {
                  current = *it;
                  ++it;
                  matchLength += current;
                  blockOffset++;
               } while (current == 255);
            }

            // copy match
            uint32_t referencePos = (pos >= delta) ? (pos - delta) : (HISTORY_SIZE + pos - delta);
            // start and end within the current 64k block ?
            if (pos + matchLength < HISTORY_SIZE && referencePos + matchLength < HISTORY_SIZE) {
               // read/write continuous block (no wrap-around at the end of history[])
               // fast copy
               if (pos >= referencePos + matchLength || referencePos >= pos + matchLength) {
                  // non-overlapping
                  memcpy(history + pos, history + referencePos, matchLength);
                  pos += matchLength;
               }
               else {
                  // overlapping, slower byte-wise copy
                  while (matchLength-- > 0) history[pos++] = history[referencePos++];
               }
            }
            else {
               // either read or write wraps around at the end of history[]
               while (matchLength-- > 0) {
                  // copy single byte
                  history[pos++] = history[referencePos++];

                  // cannot write anymore ? => wrap around
                  if (pos == HISTORY_SIZE) {
                     // flush output buffer
                     smallz4::dump({history, HISTORY_SIZE}, b, ix);
                     numWritten += HISTORY_SIZE;
                     pos = 0;
                  }
                  // wrap-around of read location
                  referencePos %= HISTORY_SIZE;
               }
            }
         }
      }
      else {
         // copy uncompressed data and add to history, too (if next block is compressed and some matches refer to this
         // block)
         while (blockSize-- > 0) {
            // copy a byte ...
            history[pos++] = *it;
            ++it;
            // ... until buffer is full => send to output
            if (pos == HISTORY_SIZE) {
               smallz4::dump({history, HISTORY_SIZE}, b, ix);
               pos = 0;
            }
         }
      }

      if (hasBlockChecksum) {
         it += 4; // ignore checksum, skip 4 bytes
      }
   }

   if (hasContentChecksum) {
      it += 4; // ignore checksum, skip 4 bytes
   }

   smallz4::dump({history, pos}, b, ix);
}

#include <lz4.h>

#include <chrono>
#include <iostream>
#include <random>

void decompress_lz4(const std::string& compressedText)
{
   // Decompress the string
   std::string decompressedText(compressedText.size() * 10, '\0'); // Allocate space for decompressed data

   int decompressedSize = LZ4_decompress_safe(compressedText.c_str(), &decompressedText[0], int(compressedText.size()),
                                              int(decompressedText.size()));

   if (decompressedSize < 0) {
      std::cerr << "Decompression failed.\n";
   }
   else {
      // Resize the decompressed string to the actual size
      decompressedText.resize(decompressedSize);
   }
}

void test_lz4(const std::string& originalText)
{
   const char* input = originalText.c_str();
   const int inputSize = static_cast<int>(originalText.size());
   int maxCompressedSize = LZ4_compressBound(inputSize); // Calculate maximum compressed size
   std::string compressedText(maxCompressedSize, '\0'); // Allocate space for compressed data

   auto t0 = std::chrono::steady_clock::now();
   int compressedSize = LZ4_compress_default(input, &compressedText[0], inputSize, maxCompressedSize);
   auto t1 = std::chrono::steady_clock::now();

   std::cout << "lz4 compression time: "
             << std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() * 1e-6 << '\n';

   if (compressedSize <= 0) {
      std::cerr << "Compression failed." << '\n';
   }

   compressedText.resize(compressedSize);

   std::cout << "lz4: " << originalText.size() << ", " << compressedText.size() << '\n';

   decompress_lz4(compressedText);
}

std::string original_in{};
std::string original_out{};
size_t original_ix{};

/// read several bytes and store at "data", return number of actually read bytes (return only zero if end of data
/// reached)
size_t getBytesOriginal(void* data, size_t numBytes, void*)
{
   if (data && numBytes > 0) {
      const auto n = original_in.size();

      if ((numBytes + original_ix) > n) {
         numBytes = n - original_ix;
      }

      std::memcpy(data, original_in.data() + original_ix, numBytes);
      original_ix += numBytes;

      return numBytes;
   }
   return 0;
}

/// write a block of bytes
void sendBytesOriginal(const void* data, size_t numBytes, void*)
{
   if (data && numBytes > 0) {
      const auto n = original_out.size();
      original_out.resize(n + numBytes);

      std::memcpy(original_out.data() + n, data, numBytes);
   }
}

int main(int argc, const char* argv[])
{
   std::string text =
      "LZ4 text compression, an efficient algorithm developed by Yann Collet in 2011, stands out for its remarkable "
      "speed and compression ratios, making it a preferred choice for numerous applications. By leveraging a "
      "combination of fast parsing and a powerful dictionary-based approach, LZ4 excels in compressing text data with "
      "minimal computational overhead, achieving impressive compression ratios while maintaining rapid decompression "
      "speeds. Its popularity stems from its seamless integration into various systems and its ability to handle "
      "real-time data processing requirements with ease. From reducing storage overhead in databases to accelerating "
      "data transmission over networks, LZ4's effectiveness in compressing text data has made it a cornerstone "
      "technology in the realm of data compression, offering both efficiency and speed without compromising on "
      "performance.";

   std::uniform_int_distribution<uint8_t> dist{40, 45};
   std::mt19937_64 generator{};
   for (size_t i = 0; i < 5'000'000; ++i) {
      text.push_back(dist(generator));
   }

   // std::string text = "Hello World. Hello World!";

   test_lz4(text);
   std::cout << '\n';

   uint16_t maxChainLength = 3;

   {
      original_in = text;
      auto t0 = std::chrono::steady_clock::now();
      smallz4_original::lz4(getBytesOriginal, sendBytesOriginal, maxChainLength);
      auto t1 = std::chrono::steady_clock::now();

      std::cout << "original compression time: "
                << std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() * 1e-6 << '\n';

      std::cout << "original: " << original_in.size() << ", " << original_out.size() << '\n';
      std::cout << '\n';
   }

   std::string compressed{};
   size_t ix{};

   const unsigned char* it = reinterpret_cast<const unsigned char*>(text.data());
   const unsigned char* end = it + text.size();

   auto t0 = std::chrono::steady_clock::now();
   smallz4::lz4(it, end, compressed, ix, maxChainLength);
   auto t1 = std::chrono::steady_clock::now();

   std::cout << "smallz4 compression time: "
             << std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() * 1e-6 << '\n';
   compressed.resize(ix);

   std::cout << "refactored: " << text.size() << ", " << compressed.size() << '\n';
   // std::cout << compressed << '\n';

   std::cout << '\n';
   if (original_out == compressed) {
      std::cout << "refactored matches original!\n";
   }

   it = reinterpret_cast<const unsigned char*>(compressed.data());
   end = it + compressed.size();
   ix = 0;
   std::string decompressed{};
   unlz4(it, end, decompressed, ix, nullptr);
   decompressed.resize(ix);
   if (decompressed == text) {
      std::cout << "decompression succeeded!\n";
   }
   
   //decompress_lz4(compressed);

   std::cout << '\n';

   return 0;
}
