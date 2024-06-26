// Copyright (c) 2016-2020 Stephan Brumme. All rights reserved.
// see https://create.stephan-brumme.com/smallz4/
// see LICENSE for details

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

// Compression levels:
// 0: No compression
// 1 - 3: Greedy search, check 1 to 3 matches
// 4 - 8: Lazy matching with optimal parsing, check 4 to 8 matches
// 9: Optimal parsing, check all possible matches (default)

/// LZ4 compression with optimal parsing
struct smallz4
{
   /// compress everything in input stream (accessed via getByte) and write to output stream (via send)
   static void lz4(const unsigned char*& it, const unsigned char* end, std::string& b, size_t& ix,
                   uint16_t maxChainLength = MaxChainLength, const std::vector<unsigned char>& dictionary = {})
   {
      smallz4 obj(maxChainLength);
      obj.compress(it, end, b, ix, dictionary);
   }

   // compression level thresholds
   /// greedy mode for short chains (compression level <= 3) instead of optimal parsing / lazy evaluation
   static constexpr int ShortChainsGreedy = 3;
   /// lazy evaluation for medium-sized chains (compression level > 3 and <= 6)
   static constexpr int ShortChainsLazy = 6;

   static inline void dump(const std::span<const unsigned char> str, std::string& b, size_t& ix) noexcept
   {
      const auto n = str.size();
      if (ix + n > b.size()) [[unlikely]] {
         b.resize((std::max)(b.size() * 2, ix + n));
      }

      std::memcpy(b.data() + ix, str.data(), n);
      ix += n;
   }
   
   static inline void dump(const std::span<const unsigned char> str, std::vector<unsigned char>& b, size_t& ix) noexcept
   {
      const auto n = str.size();
      if (ix + n > b.size()) [[unlikely]] {
         b.resize((std::max)(b.size() * 2, ix + n));
      }

      std::memcpy(b.data() + ix, str.data(), n);
      ix += n;
   }

   static inline void dump(const unsigned char c, std::string& b, size_t& ix) noexcept
   {
      if (ix == b.size()) [[unlikely]] {
         b.resize(b.size() == 0 ? 128 : b.size() * 2);
      }

      b[ix] = c;
      ++ix;
   }
   
   static inline void dump(const unsigned char c, std::vector<unsigned char>& b, size_t& ix) noexcept
   {
      if (ix == b.size()) [[unlikely]] {
         b.resize(b.size() == 0 ? 128 : b.size() * 2);
      }

      b[ix] = c;
      ++ix;
   }

   static inline void dump_type(auto&& value, std::string& b, size_t& ix) noexcept
   {
      constexpr auto n = sizeof(std::decay_t<decltype(value)>);
      if (ix + n > b.size()) [[unlikely]] {
         b.resize((std::max)(b.size() * 2, ix + n));
      }

      std::memcpy(b.data() + ix, &value, n);
      ix += n;
   }

  private:
   /// a block can be up to 4 MB
   using Length = uint32_t;
   /// matches must start within the most recent 64k
   using Distance = uint16_t;

   static constexpr int MinMatch = 4; // each match's length must be >= 4
   static constexpr int JustLiteral = 1; // a literal needs one byte
   static constexpr int BlockEndNoMatch = 12; // last match must not be closer than 12 bytes to the end
   static constexpr int BlockEndLiterals = 5; // last 5 bytes must be literals, no matching allowed
   static constexpr int HashBits = 20; // match finder's hash table size (2^HashBits entries, must be less than 32)
   static constexpr int HashSize = 1 << HashBits;
   static constexpr uint16_t MaxDistance = 65535; // maximum match distance, must be power of 2 minus 1
   static constexpr int EndOfChain = 0; // marker for "no match"
   static constexpr uint16_t MaxChainLength =
      MaxDistance; // stop match finding after MaxChainLength steps (default is MaxDistance => optimal parsing)

   static constexpr int MaxSameLetter =
      19 +
      255 * 256; // significantly speed up parsing if the same byte is repeated a lot, may cause sub-optimal compression

   /// maximum block size as defined in LZ4 spec: { 0,0,0,0,64*1024,256*1024,1024*1024,4*1024*1024 }
   /// I only work with the biggest maximum block size (7)
   //  note: xxhash header checksum is precalculated only for 7, too
   static constexpr int MaxBlockSizeId = 7;
   static constexpr int MaxBlockSize = 4 * 1024 * 1024;

   // number of literals and match length is encoded in several bytes, max 255 per byte
   static constexpr int MaxLengthCode = 255;

   //  ----- one and only variable ... -----

   /// how many matches are checked in findLongestMatch, lower values yield faster encoding at the cost of worse
   /// compression ratio
   uint16_t maxChainLength{};
   
   struct Matches
   {
      std::vector<Length> lengths{}; // lengths of matches
      std::vector<Distance> distances{}; // distances of matches
   };

   /// create new compressor (only invoked by lz4)
   explicit smallz4(uint16_t newMaxChainLength = MaxChainLength) : maxChainLength(newMaxChainLength) {}

   /// return true, if the four bytes at *a and *b match
   inline static constexpr bool match4(const void* const a, const void* const b) noexcept
   {
      return *(const uint32_t*)a == *(const uint32_t*)b;
   }

   /// simple hash function, input: 32 bits, output: HashBits bits (by default: 20)
   inline static constexpr uint32_t getHash32(const uint32_t fourBytes)
   {
      // taken from https://en.wikipedia.org/wiki/Linear_congruential_generator
      constexpr uint32_t HashMultiplier = 48271;
      return ((fourBytes * HashMultiplier) >> (32 - HashBits)) & (HashSize - 1);
   }

   /// find longest match of data[pos] between data[begin] and data[end], use match chain
   void findLongestMatch(const unsigned char* const data, uint64_t pos, uint64_t begin, uint64_t end,
                          const Distance* const chain, Length& result_length, Distance& result_distance) const
   {
      result_length = JustLiteral; // assume a literal => one byte

      // compression level: look only at the first n entries of the match chain
      uint16_t stepsLeft = maxChainLength;
      // findLongestMatch() shouldn't be called when maxChainLength = 0 (uncompressed)

      // pointer to position that is currently analyzed (which we try to find a great match for)
      const unsigned char* const current = data + pos - begin;
      // don't match beyond this point
      const unsigned char* const stop = current + end - pos;

      // get distance to previous match, abort if 0 => not existing
      Distance distance = chain[pos & MaxDistance];
      uint32_t totalDistance = 0;
      while (distance != EndOfChain) {
         // chain goes too far back ?
         totalDistance += distance;
         if (totalDistance > MaxDistance) {
            break; // can't match beyond 64k
         }
         
         distance = chain[(pos - totalDistance) & MaxDistance]; // prepare next position

         // let's introduce a new pointer atLeast that points to the first "new" byte of a potential longer match
         const unsigned char* const atLeast = current + result_length + 1;
         // impossible to find a longer match because not enough bytes left ?
         if (atLeast > stop) {
            break;
         }

         // the idea is to split the comparison algorithm into 2 phases
         // (1) scan backward from atLeast to current, abort if mismatch
         // (2) scan forward  until a mismatch is found and store length/distance of this new best match
         // current                  atLeast
         //    |                        |
         //    -<<<<<<<< phase 1 <<<<<<<<
         //                              >>> phase 2 >>>
         // main reason for phase 1:
         // - both byte sequences start with the same bytes, quite likely they are very similar
         // - there is a good chance that if they differ, then their last bytes differ
         // => checking the last first increases the probability that a mismatch is detected as early as possible

         // compare 4 bytes at once
         constexpr Length CheckAtOnce = 4;

         // all bytes between current and atLeast shall be identical
         const unsigned char* phase1 = atLeast - CheckAtOnce; // minus 4 because match4 checks 4 bytes
         while (phase1 > current && match4(phase1, phase1 - totalDistance)) {
            phase1 -= CheckAtOnce;
         }
         // note: - the first four bytes always match
         //       - in the last iteration, phase1 points either at current + 1 or current + 2 or current + 3
         //       - therefore we compare a few bytes twice => but a check to skip these checks is more expensive

         // mismatch ? (the while-loop was aborted)
         if (phase1 > current) {
            continue;
         }

         // we have a new best match, now scan forward
         const unsigned char* phase2 = atLeast;

         // fast loop: check four bytes at once
         while (phase2 + CheckAtOnce <= stop && match4(phase2, phase2 - totalDistance)) {
            phase2 += CheckAtOnce;
         }
         // slow loop: check the last 1/2/3 bytes
         while (phase2 < stop && *phase2 == *(phase2 - totalDistance)) {
            ++phase2;
         }
         
         // store new best match
         result_length = Length(phase2 - current);
         result_distance = Distance(totalDistance);

         // stop searching on lower compression levels
         if (--stepsLeft == 0) {
            break;
         }
      }
   }

   /// create shortest output
   /** data points to block's begin; we need it to extract literals **/
   static void selectBestMatches(const Matches& matches,
                                                       const unsigned char* const data, std::vector<unsigned char>& result)
   {
      const auto n_matches = matches.lengths.size();
      result.resize(n_matches);
      size_t ix{}; // write index for result

      // indices of current run of literals
      size_t literalsFrom = 0;
      size_t numLiterals = 0;

      bool lastToken = false;

      // walk through the whole block
      for (size_t offset = 0; offset < n_matches;) // increment inside of loop
      {
         const auto length = matches.lengths[offset]; // get best cost-weighted match
         const auto distance = matches.distances[offset]; // get best cost-weighted match

         // if no match, then count literals instead
         if (length <= JustLiteral) {
            // first literal ? need to reset pointers of current sequence of literals
            if (numLiterals == 0) {
               literalsFrom = offset;
            }
            
            ++numLiterals; // add one more literal to current sequence
            ++offset; // next match

            // continue unless it's the last literal
            if (offset < n_matches) {
               continue;
            }

            lastToken = true;
         }
         else {
            offset += length; // skip unused matches
         }

         // store match length (4 is implied because it's the minimum match length)
         // last token has zero length
         int matchLength = lastToken ? 0 : (int(length) - MinMatch);

         // token consists of match length and number of literals, let's start with match length ...
         unsigned char token = (matchLength < 15) ? (unsigned char)matchLength : 15;

         // >= 15 literals ? (extra bytes to store length)
         if (numLiterals < 15) {
            // add number of literals in higher four bits
            token |= numLiterals << 4;
            dump(token, result, ix);
         }
         else {
            // set all higher four bits, the following bytes with determine the exact number of literals
            dump(token | 0xF0, result, ix);

            // 15 is already encoded in token
            int encodeNumLiterals = int(numLiterals) - 15;

            // emit 255 until remainder is below 255
            while (encodeNumLiterals >= MaxLengthCode) {
               dump(MaxLengthCode, result, ix);
               encodeNumLiterals -= MaxLengthCode;
            }
            // and the last byte (can be zero, too)
            dump((unsigned char)encodeNumLiterals, result, ix);
         }
         // copy literals
         if (numLiterals > 0) {
            dump({ data + literalsFrom, numLiterals }, result, ix);

            // last token doesn't have a match
            if (lastToken) {
               break;
            }
            
            numLiterals = 0; // reset
         }

         // distance stored in 16 bits / little endian
         dump(distance & 0xFF, result, ix);
         dump(distance >> 8, result, ix);

         // >= 15+4 bytes matched
         if (matchLength >= 15) {
            // 15 is already encoded in token
            matchLength -= 15;
            // emit 255 until remainder is below 255
            while (matchLength >= MaxLengthCode) {
               dump(MaxLengthCode, result, ix);
               matchLength -= MaxLengthCode;
            }
            // and the last byte (can be zero, too)
            dump((unsigned char)matchLength, result, ix);
         }
      }
      
      result.resize(ix);
   }

   /// walk backwards through all matches and compute number of compressed bytes from current position to the end of the
   /// block
   /** note: matches are modified (shortened length) if necessary **/
   static void estimateCosts(Matches& matches)
   {
      const size_t blockEnd = matches.lengths.size();

      // equals the number of bytes after compression
      using Cost = uint32_t;
      // minimum cost from this position to the end of the current block
      std::vector<Cost> cost(blockEnd, 0);
      // "cost" represents the number of bytes needed

      // the last bytes must always be literals
      Length numLiterals = BlockEndLiterals;
      // backwards optimal parsing
      for (int64_t i = int64_t(blockEnd) - (1 + BlockEndLiterals); i >= 0;
           --i) // ignore the last 5 bytes, they are always literals
      {
         // if encoded as a literal
         ++numLiterals;
         Length bestLength = JustLiteral;
         // such a literal "costs" 1 byte
         Cost minCost = cost[i + 1] + JustLiteral;

         // an extra length byte is required for every 255 literals
         if (numLiterals >= 15) {
            // same as: if ((numLiterals - 15) % MaxLengthCode == 0)
            // but I try hard to avoid the slow modulo function
            if (numLiterals == 15 || (numLiterals >= 15 + MaxLengthCode && (numLiterals - 15) % MaxLengthCode == 0))
               minCost++;
         }

         // let's look at the longest match, almost always more efficient that the plain literals
         const Length match_length = matches.lengths[i];
         const Distance match_distance = matches.distances[i];

         // very long self-referencing matches can slow down the program A LOT
         if (match_length >= MaxSameLetter && match_distance == 1) {
            // assume that longest match is always the best match
            // NOTE: this assumption might not be optimal !
            bestLength = match_length;
            minCost = cost[i + match_length] + 1 + 2 + 1 + Cost(match_length - 19) / 255;
         }
         else {
            // this is the core optimization loop

            // overhead of encoding a match: token (1 byte) + offset (2 bytes) + sometimes extra bytes for long matches
            Cost extraCost = 1 + 2;
            Length nextCostIncrease = 18; // need one more byte for 19+ long matches (next increase: 19+255*x)

            // try all match lengths (start with short ones)
            for (Length length = MinMatch; length <= match_length; ++length) {
               // token (1 byte) + offset (2 bytes) + extra bytes for long matches
               Cost currentCost = cost[i + length] + extraCost;
               // better choice ?
               if (currentCost <= minCost) {
                  // regarding the if-condition:
                  // "<"  prefers literals and shorter matches
                  // "<=" prefers longer matches
                  // they should produce the same number of bytes (because of the same cost)
                  // ... but every now and then it doesn't !
                  // that's why: too many consecutive literals require an extra length byte
                  // (which we took into consideration a few lines above)
                  // but we only looked at literals beyond the current position
                  // if there are many literal in front of the current position
                  // then it may be better to emit a match with the same cost as the literals at the current position
                  // => it "breaks" the long chain of literals and removes the extra length byte
                  minCost = currentCost;
                  bestLength = length;
                  // performance-wise, a long match is usually faster during decoding than multiple short matches
                  // on the other hand, literals are faster than short matches as well (assuming same cost)
               }

               // very long matches need extra bytes for encoding match length
               if (length == nextCostIncrease) {
                  ++extraCost;
                  nextCostIncrease += MaxLengthCode;
               }
            }
         }

         // store lowest cost so far
         cost[i] = minCost;

         // and adjust best match
         matches.lengths[i] = bestLength;
         
         if (bestLength != JustLiteral) {
            numLiterals = 0; // reset number of literals if a match was chosen
         }

         // note: if bestLength is smaller than the previous matches[i].length then there might be a closer match
         //       which could be more cache-friendly (=> faster decoding)
      }
   }

   void compress(const unsigned char*& it, const unsigned char* end, std::string& b, size_t& ix,
                 const std::vector<unsigned char>& dictionary) const
   {
      // ==================== write header ====================
      // frame header
      const unsigned char header[] = {
         0x04,
         0x22,
         0x4D,
         0x18, // magic bytes
         1 << 6, // flags: no checksums, blocks depend on each other and no dictionary ID
         MaxBlockSizeId << 4, // max blocksize
         0xDF // header checksum (precomputed)
      };
      dump({header, sizeof(header)}, b, ix);

      // ==================== declarations ====================
      // data will contain only bytes which are relevant for the current block
      std::span<const unsigned char> data;
      
      size_t dataZero = 0; // file position corresponding to data[0]
      size_t numRead = 0; // last already read position

      // passthru data ? (but still wrap it in LZ4 format)
      const bool uncompressed = (maxChainLength == 0);

      // last time we saw a hash
      constexpr uint64_t NoLastHash = ~0; // = -1
      std::vector<uint64_t> lastHash(HashSize, NoLastHash);

      // previous position which starts with the same bytes
      std::vector<Distance> previousHash(MaxDistance + 1, Distance(EndOfChain)); // long chains based on my simple hash
      std::vector<Distance> previousExact(
         MaxDistance + 1, Distance(EndOfChain)); // shorter chains based on exact matching of the first four bytes
      // these two containers are essential for match finding:
      // 1. I compute a hash of four byte
      // 2. in lastHash is the location of the most recent block of four byte with that same hash
      // 3. due to hash collisions, several groups of four bytes may yield the same hash
      // 4. so for each location I can look up the previous location of the same hash in previousHash
      // 5. basically it's a chain of memory locations where potential matches start
      // 5. I follow this hash chain until I find exactly the same four bytes I was looking for
      // 6. then I switch to a sparser chain: previousExact
      // 7. it's basically the same idea as previousHash but this time not the hash but the first four bytes must be
      // identical
      // 8. previousExact will be used by findLongestMatch: it compare all such strings and figures out which is the
      // longest match

      // And why do I have to do it in such a complicated way ?
      // - well, there are 2^32 combinations of four bytes
      // - so that there are 2^32 potential chains
      // - most combinations just don't occur and occupy no space but I still have to keep their "entry point" (which
      // are empty/invalid)
      // - that would be at least 16 GBytes RAM (2^32 x 4 bytes)
      // - my hashing algorithm reduces the 2^32 combinations to 2^20 hashes (see hashBits), that's about 8 MBytes RAM
      // - thus only 2^20 entry points and at most 2^20 hash chains which is easily manageable
      // ... in the end it's all about conserving memory !

      // first and last offset of a block (nextBlock is end-of-block plus 1)
      uint64_t lastBlock = 0;
      uint64_t nextBlock = 0;
      bool parseDictionary = !dictionary.empty();

      // main loop, processes one block per iteration
      while (true) {
         // ==================== start new block ====================
         // first byte of the currently processed block (data may contain the last 64k of the previous block, too)
         const unsigned char* dataBlock = nullptr;
         
         // prepend dictionary
         if (parseDictionary) {
            throw std::runtime_error("parseDictionary doesn't work with the single buffer approach, need to add a compile time option for a dictionary buffer");
            // copy only the most recent 64k of the dictionary
            if (dictionary.size() < MaxDistance) {
               data = {dictionary.data(), dictionary.size()};
            }
            else {
               data = {dictionary.data(), MaxDistance};
            }
            
            nextBlock = data.size();
            numRead = data.size();
         }
         
         // read more bytes from input
         if (const size_t incoming = size_t(end - it); incoming)
         {
            if (data.empty()) {
               data = {it, incoming};
            }
            else {
               data = {data.data(), data.size() + incoming};
            }
            numRead += incoming;
            it += incoming;
         }
         
         if (nextBlock == numRead) {
            break; // finished reading
         }
         
         constexpr size_t maxBlockSize = MaxBlockSize;
         // determine block borders
         lastBlock = nextBlock;
         nextBlock += maxBlockSize;
         // not beyond end-of-file
         if (nextBlock > numRead) {
            nextBlock = numRead;
         }
         
         // pointer to first byte of the currently processed block (the container named data may contain the
         // last 64k of the previous block, too)
         dataBlock = &data[lastBlock - dataZero];
         
         const uint64_t blockSize = nextBlock - lastBlock;
         
         // ==================== full match finder ====================
         
         // greedy mode is much faster but produces larger output
         const bool isGreedy = (maxChainLength <= ShortChainsGreedy);
         // lazy evaluation: if there is a match, then try running match finder on next position, too, but not after
         // that
         const bool isLazy = !isGreedy && (maxChainLength <= ShortChainsLazy);
         // skip match finding on the next x bytes in greedy mode
         Length skipMatches = 0;
         // allow match finding on the next byte but skip afterwards (in lazy mode)
         bool lazyEvaluation = false;
         
         // the last literals of the previous block skipped matching, so they are missing from the hash chains
         int64_t lookback = int64_t(dataZero);
         if (lookback > BlockEndNoMatch && !parseDictionary) {
            lookback = BlockEndNoMatch;
         }
         if (parseDictionary) {
            lookback = int64_t(dictionary.size());
         }
         // so let's go back a few bytes
         lookback = -lookback;
         if (uncompressed) {
            lookback = 0;
         }
         
         const auto n_matches = (uncompressed ? 0 : blockSize);
         Matches matches;
         matches.lengths.resize(n_matches);
         matches.distances.resize(n_matches);
         // find longest matches for each position (skip if level=0 which means "uncompressed")
         int64_t i;
         for (i = lookback; i + BlockEndNoMatch <= int64_t(blockSize) && !uncompressed; ++i) {
            // detect self-matching
            if (i > 0 && dataBlock[i] == dataBlock[i - 1]) {
               // predecessor had the same match ?
               if (matches.distances[i - 1] == 1) // TODO: handle very long self-referencing matches
               {
                  const auto prev_length = matches.lengths[i - 1];
                  if (prev_length > MaxSameLetter) {
                     // just copy predecessor without further (expensive) optimizations
                     matches.distances[i] = 1;
                     matches.lengths[i] = prev_length - 1;
                     continue;
                  }
               }
            }
            
            uint32_t four; // read next four bytes
            std::memcpy(&four, dataBlock + i, 4);
            const uint32_t hash = getHash32(four); // convert to a shorter hash
            
            uint64_t lastHashMatch = lastHash[hash]; // get most recent position of this hash
            lastHash[hash] = i + lastBlock; // and store current position
            
            // remember: i could be negative, too
            const Distance prevIndex = (i + MaxDistance + 1) & MaxDistance; // actually the same as i & MaxDistance
            
            // no predecessor / no hash chain available ?
            if (lastHashMatch == NoLastHash) {
               previousHash[prevIndex] = EndOfChain;
               previousExact[prevIndex] = EndOfChain;
               continue;
            }
            
            // most recent hash match too far away ?
            uint64_t distance = lastHash[hash] - lastHashMatch;
            if (distance > MaxDistance) {
               previousHash[prevIndex] = EndOfChain;
               previousExact[prevIndex] = EndOfChain;
               continue;
            }
            
            // build hash chain, i.e. store distance to last pseudo-match
            previousHash[prevIndex] = Distance(distance);
            
            // skip pseudo-matches (hash collisions) and build a second chain where the first four bytes must match
            // exactly
            uint32_t currentFour;
            // check the hash chain
            while (true) {
               // read four bytes
               std::memcpy(&currentFour, &data[lastHashMatch - dataZero], 4); // match may be found in the previous block, too
               // match chain found, first 4 bytes are identical
               if (currentFour == four) {
                  break;
               }
               
               // prevent from accidently hopping on an old, wrong hash chain
               if (hash != getHash32(currentFour)) {
                  break;
               }
               
               // try next pseudo-match
               const Distance next = previousHash[lastHashMatch & MaxDistance];
               // end of the hash chain ?
               if (next == EndOfChain) {
                  break;
               }
               
               // too far away ?
               distance += next;
               if (distance > MaxDistance) {
                  break;
               }
               
               // take another step along the hash chain ...
               lastHashMatch -= next;
               // closest match is out of range ?
               if (lastHashMatch < dataZero) {
                  break;
               }
            }
            
            // search aborted / failed ?
            if (four != currentFour) {
               // no matches for the first four bytes
               previousExact[prevIndex] = EndOfChain;
               continue;
            }
            
            // store distance to previous match
            previousExact[prevIndex] = (Distance)distance;
            
            // no matching if crossing block boundary, just update hash tables
            if (i < 0) {
               continue;
            }
            
            // skip match finding if in greedy mode
            if (skipMatches > 0) {
               --skipMatches;
               if (!lazyEvaluation) {
                  continue;
               }
               lazyEvaluation = false;
            }
            
            // and after all that preparation ... finally look for the longest match
            auto& length = matches.lengths[i];
            findLongestMatch(data.data(), i + lastBlock, dataZero, nextBlock - BlockEndLiterals,
                                          previousExact.data(), length, matches.distances[i]);
            
            // no match finding needed for the next few bytes in greedy/lazy mode
            if ((isLazy || isGreedy) && length != JustLiteral) {
               lazyEvaluation = (skipMatches == 0);
               skipMatches = length;
            }
         }
         // last bytes are always literals
         const auto n_lengths = int64_t(n_matches);
         while (i < n_lengths) {
            matches.lengths[i] = JustLiteral;
            ++i;
         }
         
         // dictionary is valid only to the first block
         parseDictionary = false;
         
         // ==================== estimate costs (number of compressed bytes) ====================
         
         // not needed in greedy mode and/or very short blocks
         if (n_matches > BlockEndNoMatch && maxChainLength > ShortChainsGreedy) {
            estimateCosts(matches);
         }
         
         // ==================== select best matches ====================
         
         std::vector<unsigned char> compressed{};
         selectBestMatches(matches, &data[lastBlock - dataZero], compressed);

         // ==================== output ====================

         // did compression do harm ?
         const bool useCompression = compressed.size() < blockSize && !uncompressed;

         // block size
         uint32_t numBytes = uint32_t(useCompression ? compressed.size() : blockSize);
         uint32_t numBytesTagged = numBytes | (useCompression ? 0 : 0x80000000);
         unsigned char num1 = numBytesTagged & 0xFF;
         dump(num1, b, ix);
         unsigned char num2 = (numBytesTagged >> 8) & 0xFF;
         dump(num2, b, ix);
         unsigned char num3 = (numBytesTagged >> 16) & 0xFF;
         dump(num3, b, ix);
         unsigned char num4 = (numBytesTagged >> 24) & 0xFF;
         dump(num4, b, ix);

         if (useCompression) {
            dump({compressed.data(), numBytes}, b, ix);
         }
         else {
            // uncompressed ? => copy input data
            dump({&data[lastBlock - dataZero], numBytes}, b, ix);
         }

         // remove already processed data except for the last 64kb which could be used for intra-block matches
         if (data.size() > MaxDistance) {
            const size_t remove = data.size() - MaxDistance;
            dataZero += remove;
            data = data.subspan(remove);
         }
      }

      constexpr uint32_t zero = 0;
      dump_type(zero, b, ix);
   }
};
