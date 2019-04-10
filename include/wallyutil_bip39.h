// takes `ent` (entropy size) and returns the
// number of words in the mnemonic, or -1 if
// ent is not a valid size for bip39
int bip39_word_count_from_entropy_size(int ent);

// takes `wc` (word count) and returns the
// corresponding entropy size, or -1 if the
// word count is not valid for bip39
int bip39_entropy_size_from_word_count(int wc);
