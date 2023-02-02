#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stdint.h>
#include "wb_aes.h"
#include "linear_ops.h"
#include "nonlinear_ops.h"
#include "wb_aes_gen.h"
#include "util.h"
#include "test.h"
#include "test_util.h"

extern uint8_t SBox[256];
extern uint8_t ISBox[256];
extern void shift_rows(uint8_t state[4][4]);

void wb_aes_decrypt(char *in, char *out)
{
	gf2matrix *mix_columns_mixing_bijection, *inv_mix_columns_mixing_bijection;
	tbox_mixing_bijections_t tbox_mixing_bijections, inv_tbox_mixing_bijections;
	gf2matrix *initial_encoding, *initial_decoding;
	gf2matrix *final_encoding, *final_decoding;
	tbox_t tbox;
	typeIA_t typeIAs;
	typeII_t typeIIs;
	typeIII_t typeIIIs;
	typeIB_t typeIBs;
	typeIV_IA_t typeIV_IAs;
	typeIV_IB_t typeIV_IBs;
	typeIV_II_round_t typeIV_IIs[NR - 1];
	typeIV_III_round_t typeIV_IIIs[NR - 1];
	uint32_t key_schedule[4 * (NR + 1)];
	uint8_t key[KEY_SIZE];

	sboxes_8bit_t typeIA_input_sbox, typeIA_input_sbox_inv;
	sboxes_128bit_t typeIA_interim_sbox, typeIA_interim_sbox_inv;
	sboxes_8bit_t typeII_input_sbox[NR], typeII_input_sbox_inv[NR];
	sboxes_32bit_t typeII_interim_sbox[NR - 1], typeII_interim_sbox_inv[NR - 1];
	sboxes_8bit_t typeII_output_sbox[NR - 1], typeII_output_sbox_inv[NR - 1];
	sboxes_32bit_t typeIII_interim_sbox[NR - 1], typeIII_interim_sbox_inv[NR
			- 1];
	sboxes_128bit_t typeIB_interim_sbox, typeIB_interim_sbox_inv;
	sboxes_8bit_t typeIB_output_sbox, typeIB_output_sbox_inv;
	uint8_t state[4][4];
	_4bit_strip32_t strips32;
	_4bit_strip128_t strips128;
	int round, row, col, i;
	uint32_t mixed_key_schedule[4 * (NR + 1)];
	uint8_t dec_out[16];

	int tries = 3;
	for (; tries != 0; --tries) {
		randomize_key(key);
		
		// start decrypting the same thing
		// at the end we should get the input
		make_block_invertible_matrix_pair(&mix_columns_mixing_bijection,
				&inv_mix_columns_mixing_bijection, 32);
		make_tbox_mixing_bijections(tbox_mixing_bijections,
				inv_tbox_mixing_bijections);

		make_block_invertible_matrix_pair(&initial_encoding, &initial_decoding, 128);
		make_block_invertible_matrix_pair(&final_encoding, &final_decoding, 128);

		//expand_key(key, SBox, mixed_key_schedule, 4);
		mix_expanded_key(key_schedule);
		make_inv_tbox(tbox, ISBox, key_schedule, tbox_mixing_bijections);
		make_sbox_pair_8(typeIA_input_sbox, typeIA_input_sbox_inv);
		make_sbox_pair_128(typeIA_interim_sbox, typeIA_interim_sbox_inv);
		make_rounds_sbox_pair_8(typeII_input_sbox, typeII_input_sbox_inv, NR);
		make_rounds_sbox_pair_32(typeII_interim_sbox, typeII_interim_sbox_inv,
				NR - 1);
		make_rounds_sbox_pair_8(typeII_output_sbox, typeII_output_sbox_inv, NR - 1);
		make_rounds_sbox_pair_32(typeIII_interim_sbox, typeIII_interim_sbox_inv,
				NR - 1);
		make_sbox_pair_128(typeIB_interim_sbox, typeIB_interim_sbox_inv);
		make_sbox_pair_8(typeIB_output_sbox, typeIB_output_sbox_inv);


		make_typeIA(typeIAs, inv_tbox_mixing_bijections[NR - 1], initial_decoding,
				typeIA_input_sbox_inv, typeIA_interim_sbox);
		make_typeIV_IA(typeIV_IAs, typeIA_interim_sbox_inv,
				typeII_input_sbox[NR - 1], typeII_input_sbox_inv[NR-1]);
		make_inv_typeII(typeIIs, tbox, mix_columns_mixing_bijection,
				&typeII_input_sbox_inv[1], typeII_interim_sbox);
		make_typeIV_II(typeIV_IIs, typeII_interim_sbox_inv, typeII_output_sbox,
				typeII_output_sbox_inv);
		make_typeIII(typeIIIs, inv_mix_columns_mixing_bijection,
				inv_tbox_mixing_bijections, typeII_output_sbox_inv,
				typeIII_interim_sbox);
		make_typeIV_III(typeIV_IIIs, typeIII_interim_sbox_inv,
				typeII_input_sbox, typeII_input_sbox_inv);
		make_inv_typeIB(typeIBs, tbox[0], final_encoding,
				typeII_input_sbox_inv[0], typeIB_interim_sbox);
		make_typeIV_IB(typeIV_IBs, typeIB_interim_sbox_inv, typeIB_output_sbox,
				typeIB_output_sbox_inv);

		// the input to this stage is the output of the encryption stage
		do_input(state, in, initial_encoding, typeIA_input_sbox);

		do_typeIA(strips128, state, typeIAs);
		do_typeIV_IA(state, strips128, typeIV_IAs);
		for (round = NR - 2; round != -1; --round) {
			inv_shift_rows(state);
			do_typeII(strips32, state, typeIIs[round]);
			do_typeIV_II(state, strips32, typeIV_IIs[round]);
			do_typeIII(strips32, state, typeIIIs[round]);
			do_typeIV_III(state, strips32, typeIV_IIIs[round]);
		}
		inv_shift_rows(state);
		do_typeIB(strips128, state, typeIBs);
		do_typeIV_IB(state, strips128, typeIV_IBs);

		do_output(out, state, final_decoding, typeIB_output_sbox_inv);

		// cleanup
		free_matrix(mix_columns_mixing_bijection);
		free_matrix(inv_mix_columns_mixing_bijection);
		free_tbox_mixing_bijections(tbox_mixing_bijections);
		free_tbox_mixing_bijections(inv_tbox_mixing_bijections);
		free_matrix(final_decoding);
		free_matrix(final_encoding);
		free_matrix(initial_decoding);
		free_matrix(initial_encoding);
	}
}

void wb_aes_encrypt(char *in, char *out)
{
	gf2matrix *mix_columns_mixing_bijection, *inv_mix_columns_mixing_bijection;
	tbox_mixing_bijections_t tbox_mixing_bijections, inv_tbox_mixing_bijections;
	gf2matrix *initial_encoding, *initial_decoding;
	gf2matrix *final_encoding, *final_decoding;
	tbox_t tbox;
	typeIA_t typeIAs;
	typeII_t typeIIs;
	typeIII_t typeIIIs;
	typeIB_t typeIBs;
	typeIV_IA_t typeIV_IAs;
	typeIV_IB_t typeIV_IBs;
	typeIV_II_round_t typeIV_IIs[NR - 1];
	typeIV_III_round_t typeIV_IIIs[NR - 1];
	uint32_t key_schedule[4 * (NR + 1)];
	uint8_t key[KEY_SIZE];

	sboxes_8bit_t typeIA_input_sbox, typeIA_input_sbox_inv;
	sboxes_128bit_t typeIA_interim_sbox, typeIA_interim_sbox_inv;
	sboxes_8bit_t typeII_input_sbox[NR], typeII_input_sbox_inv[NR];
	sboxes_32bit_t typeII_interim_sbox[NR - 1], typeII_interim_sbox_inv[NR - 1];
	sboxes_8bit_t typeII_output_sbox[NR - 1], typeII_output_sbox_inv[NR - 1];
	sboxes_32bit_t typeIII_interim_sbox[NR - 1], typeIII_interim_sbox_inv[NR
			- 1];
	sboxes_128bit_t typeIB_interim_sbox, typeIB_interim_sbox_inv;
	sboxes_8bit_t typeIB_output_sbox, typeIB_output_sbox_inv;
	uint8_t state[4][4];
	_4bit_strip32_t strips32;
	_4bit_strip128_t strips128;
	int round, row, col, i;

	int tries = 3;
	for (; tries != 0; --tries) {
		randomize_key(key);
		make_block_invertible_matrix_pair(&mix_columns_mixing_bijection,
				&inv_mix_columns_mixing_bijection, 32);
		make_tbox_mixing_bijections(tbox_mixing_bijections,
				inv_tbox_mixing_bijections);

		make_block_invertible_matrix_pair(&initial_encoding, &initial_decoding, 128);
		make_block_invertible_matrix_pair(&final_encoding, &final_decoding, 128);
		expand_key(key, SBox, key_schedule, 4);
		make_tbox(tbox, SBox, key_schedule, tbox_mixing_bijections);

		make_sbox_pair_8(typeIA_input_sbox, typeIA_input_sbox_inv);
		make_sbox_pair_128(typeIA_interim_sbox, typeIA_interim_sbox_inv);
		make_rounds_sbox_pair_8(typeII_input_sbox, typeII_input_sbox_inv, NR);
		make_rounds_sbox_pair_32(typeII_interim_sbox, typeII_interim_sbox_inv,
				NR - 1);
		make_rounds_sbox_pair_8(typeII_output_sbox, typeII_output_sbox_inv, NR - 1);
		make_rounds_sbox_pair_32(typeIII_interim_sbox, typeIII_interim_sbox_inv,
				NR - 1);
		make_sbox_pair_128(typeIB_interim_sbox, typeIB_interim_sbox_inv);
		make_sbox_pair_8(typeIB_output_sbox, typeIB_output_sbox_inv);

		make_typeIA(typeIAs, inv_tbox_mixing_bijections[0], initial_decoding,
				typeIA_input_sbox_inv, typeIA_interim_sbox);
		make_typeIV_IA(typeIV_IAs, typeIA_interim_sbox_inv, typeII_input_sbox[0],
				typeII_input_sbox_inv[0]);
		make_typeII(typeIIs, tbox, mix_columns_mixing_bijection,
				typeII_input_sbox_inv, typeII_interim_sbox);
		make_typeIV_II(typeIV_IIs, typeII_interim_sbox_inv, typeII_output_sbox,
				typeII_output_sbox_inv);
		make_typeIII(typeIIIs, inv_mix_columns_mixing_bijection,
				&inv_tbox_mixing_bijections[1], typeII_output_sbox_inv,
				typeIII_interim_sbox);
		make_typeIV_III(typeIV_IIIs, typeIII_interim_sbox_inv,
				&typeII_input_sbox[1], &typeII_input_sbox_inv[1]);
		make_typeIB(typeIBs, tbox[NR - 1], final_encoding,
				typeII_input_sbox_inv[NR - 1], typeIB_interim_sbox);
		make_typeIV_IB(typeIV_IBs, typeIB_interim_sbox_inv, typeIB_output_sbox,
				typeIB_output_sbox_inv);

		do_input(state, in, initial_encoding, typeIA_input_sbox);

		do_typeIA(strips128, state, typeIAs);
		do_typeIV_IA(state, strips128, typeIV_IAs);
		for (round = 0; round < NR - 1; ++round) {
			shift_rows(state);
			do_typeII(strips32, state, typeIIs[round]);
			do_typeIV_II(state, strips32, typeIV_IIs[round]);
			do_typeIII(strips32, state, typeIIIs[round]);
			do_typeIV_III(state, strips32, typeIV_IIIs[round]);
		}
		shift_rows(state);
		do_typeIB(strips128, state, typeIBs);
		do_typeIV_IB(state, strips128, typeIV_IBs);

		do_output(out, state, final_decoding, typeIB_output_sbox_inv);

		free_matrix(mix_columns_mixing_bijection);
		free_matrix(inv_mix_columns_mixing_bijection);
		free_tbox_mixing_bijections(tbox_mixing_bijections);
		free_tbox_mixing_bijections(inv_tbox_mixing_bijections);
		free_matrix(final_decoding);
		free_matrix(final_encoding);
		free_matrix(initial_decoding);
		free_matrix(initial_encoding);
	}
}

