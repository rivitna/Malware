#! /usr/bin/env python3

# This is a Python port of the Rust reference implementation of BLAKE3:
# https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs

from __future__ import annotations
from dataclasses import dataclass

OUT_LEN = 32
KEY_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]


def mask32(x: int) -> int:
    return x & 0xFFFFFFFF


def add32(x: int, y: int) -> int:
    return mask32(x + y)


def rightrotate32(x: int, n: int) -> int:
    return mask32(x << (32 - n)) | (x >> n)


# The mixing function, G, which mixes either a column or a diagonal.
def g(state: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = add32(state[a], add32(state[b], mx))
    state[d] = rightrotate32(state[d] ^ state[a], 16)
    state[c] = add32(state[c], state[d])
    state[b] = rightrotate32(state[b] ^ state[c], 12)
    state[a] = add32(state[a], add32(state[b], my))
    state[d] = rightrotate32(state[d] ^ state[a], 8)
    state[c] = add32(state[c], state[d])
    state[b] = rightrotate32(state[b] ^ state[c], 7)


def round(state: list[int], m: list[int]) -> None:
    # Mix the columns.
    g(state, 0, 4, 8, 12, m[0], m[1])
    g(state, 1, 5, 9, 13, m[2], m[3])
    g(state, 2, 6, 10, 14, m[4], m[5])
    g(state, 3, 7, 11, 15, m[6], m[7])
    # Mix the diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9])
    g(state, 1, 6, 11, 12, m[10], m[11])
    g(state, 2, 7, 8, 13, m[12], m[13])
    g(state, 3, 4, 9, 14, m[14], m[15])


def permute(m: list[int]) -> None:
    original = list(m)
    for i in range(16):
        m[i] = original[MSG_PERMUTATION[i]]


def compress(
    chaining_value: list[int],
    block_words: list[int],
    counter: int,
    block_len: int,
    flags: int,
) -> list[int]:
    state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        mask32(counter),
        mask32(counter >> 32),
        block_len,
        flags,
    ]

    assert len(block_words) == 16
    block = list(block_words)

    round(state, block)  # round 1
    permute(block)
    round(state, block)  # round 2
    permute(block)
    round(state, block)  # round 3
    permute(block)
    round(state, block)  # round 4
    permute(block)
    round(state, block)  # round 5
    permute(block)
    round(state, block)  # round 6
    permute(block)
    round(state, block)  # round 7

    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= chaining_value[i]

    return state


def words_from_little_endian_bytes(b: bytes) -> list[int]:
    assert len(b) % 4 == 0
    return [int.from_bytes(b[i : i + 4], "little") for i in range(0, len(b), 4)]


# Each chunk or parent node can produce either an 8-word chaining value or, by
# setting the ROOT flag, any number of final output bytes. The Output struct
# captures the state just prior to choosing between those two possibilities.
@dataclass
class Output:
    input_chaining_value: list[int]
    block_words: list[int]
    counter: int
    block_len: int
    flags: int

    def chaining_value(self) -> list[int]:
        return compress(
            self.input_chaining_value,
            self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        )[:8]

    def root_output_bytes(self, length: int) -> bytes:
        output_bytes = bytearray()
        i = 0
        while i < length:
            words = compress(
                self.input_chaining_value,
                self.block_words,
                i // 64,
                self.block_len,
                self.flags | ROOT,
            )
            # The output length might not be a multiple of 4.
            for word in words:
                word_bytes = word.to_bytes(4, "little")
                take = min(len(word_bytes), length - i)
                output_bytes.extend(word_bytes[:take])
                i += take
        return output_bytes


@dataclass
class ChunkState:
    chaining_value: list[int]
    chunk_counter: int
    block: bytearray
    block_len: int
    blocks_compressed: int
    flags: int

    def __init__(self, key_words: list[int], chunk_counter: int, flags: int) -> None:
        self.chaining_value = key_words
        self.chunk_counter = chunk_counter
        self.block = bytearray(BLOCK_LEN)
        self.block_len = 0
        self.blocks_compressed = 0
        self.flags = flags

    def len(self) -> int:
        return BLOCK_LEN * self.blocks_compressed + self.block_len

    def start_flag(self) -> int:
        if self.blocks_compressed == 0:
            return CHUNK_START
        else:
            return 0

    def update(self, input_bytes: bytes) -> None:
        while input_bytes:
            # If the block buffer is full, compress it and clear it. More
            # input_bytes is coming, so this compression is not CHUNK_END.
            if self.block_len == BLOCK_LEN:
                block_words = words_from_little_endian_bytes(self.block)
                self.chaining_value = compress(
                    self.chaining_value,
                    block_words,
                    self.chunk_counter,
                    BLOCK_LEN,
                    self.flags | self.start_flag(),
                )[:8]
                self.blocks_compressed += 1
                self.block = bytearray(BLOCK_LEN)
                self.block_len = 0

            # Copy input bytes into the block buffer.
            want = BLOCK_LEN - self.block_len
            take = min(want, len(input_bytes))
            self.block[self.block_len : self.block_len + take] = input_bytes[:take]
            self.block_len += take
            input_bytes = input_bytes[take:]

    def output(self) -> Output:
        block_words = words_from_little_endian_bytes(self.block)
        return Output(
            self.chaining_value,
            block_words,
            self.chunk_counter,
            self.block_len,
            self.flags | self.start_flag() | CHUNK_END,
        )


def parent_output(
    left_child_cv: list[int],
    right_child_cv: list[int],
    key_words: list[int],
    flags: int,
) -> Output:
    return Output(
        key_words, left_child_cv + right_child_cv, 0, BLOCK_LEN, PARENT | flags
    )


def parent_cv(
    left_child_cv: list[int],
    right_child_cv: list[int],
    key_words: list[int],
    flags: int,
) -> list[int]:
    return parent_output(
        left_child_cv, right_child_cv, key_words, flags
    ).chaining_value()


# An incremental hasher that can accept any number of writes.
@dataclass
class Hasher:
    chunk_state: ChunkState
    key_words: list[int]
    cv_stack: list[list[int]]
    flags: int

    def _init(self, key_words: list[int], flags: int) -> None:
        assert len(key_words) == 8
        self.chunk_state = ChunkState(key_words, 0, flags)
        self.key_words = key_words
        self.cv_stack = []
        self.flags = flags

    # Construct a new `Hasher` for the regular hash function.
    def __init__(self) -> None:
        self._init(IV, 0)

    # Construct a new `Hasher` for the keyed hash function.
    @classmethod
    def new_keyed(cls, key: bytes) -> Hasher:
        keyed_hasher = cls()
        key_words = words_from_little_endian_bytes(key)
        keyed_hasher._init(key_words, KEYED_HASH)
        return keyed_hasher

    # Construct a new `Hasher` for the key derivation function. The context
    # string should be hardcoded, globally unique, and application-specific.
    @classmethod
    def new_derive_key(cls, context: str) -> Hasher:
        context_hasher = cls()
        context_hasher._init(IV, DERIVE_KEY_CONTEXT)
        context_hasher.update(context.encode("utf8"))
        context_key = context_hasher.finalize(KEY_LEN)
        context_key_words = words_from_little_endian_bytes(context_key)
        derive_key_hasher = cls()
        derive_key_hasher._init(context_key_words, DERIVE_KEY_MATERIAL)
        return derive_key_hasher

    # Section 5.1.2 of the BLAKE3 spec explains this algorithm in more detail.
    def add_chunk_chaining_value(self, new_cv: list[int], total_chunks: int) -> None:
        # This chunk might complete some subtrees. For each completed subtree,
        # its left child will be the current top entry in the CV stack, and
        # its right child will be the current value of `new_cv`. Pop each left
        # child off the stack, merge it with `new_cv`, and overwrite `new_cv`
        # with the result. After all these merges, push the final value of
        # `new_cv` onto the stack. The number of completed subtrees is given
        # by the number of trailing 0-bits in the new total number of chunks.
        while total_chunks & 1 == 0:
            new_cv = parent_cv(self.cv_stack.pop(), new_cv, self.key_words, self.flags)
            total_chunks >>= 1
        self.cv_stack.append(new_cv)

    # Add input to the hash state. This can be called any number of times.
    def update(self, input_bytes: bytes) -> None:
        while input_bytes:
            # If the current chunk is complete, finalize it and reset the
            # chunk state. More input is coming, so this chunk is not ROOT.
            if self.chunk_state.len() == CHUNK_LEN:
                chunk_cv = self.chunk_state.output().chaining_value()
                total_chunks = self.chunk_state.chunk_counter + 1
                self.add_chunk_chaining_value(chunk_cv, total_chunks)
                self.chunk_state = ChunkState(self.key_words, total_chunks, self.flags)

            # Compress input bytes into the current chunk state.
            want = CHUNK_LEN - self.chunk_state.len()
            take = min(want, len(input_bytes))
            self.chunk_state.update(input_bytes[:take])
            input_bytes = input_bytes[take:]

    # Finalize the hash and write any number of output bytes.
    def finalize(self, length: int = OUT_LEN) -> bytes:
        # Starting with the Output from the current chunk, compute all the
        # parent chaining values along the right edge of the tree, until we
        # have the root Output.
        output = self.chunk_state.output()
        parent_nodes_remaining = len(self.cv_stack)
        while parent_nodes_remaining > 0:
            parent_nodes_remaining -= 1
            output = parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            )
        return output.root_output_bytes(length)


# If this file is executed directly, hash standard input.
if __name__ == "__main__":
    import sys

    hasher = Hasher()
    while buf := sys.stdin.buffer.read(65536):
        hasher.update(buf)
    print(hasher.finalize().hex())
