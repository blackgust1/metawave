/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "NTCIP"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#include "EssPrecipSituation.h"

int
EssPrecipSituation_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	/* Replace with underlying type checker */
	td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
	return td->check_constraints(td, sptr, ctfailcb, app_key);
}

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static void
EssPrecipSituation_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
	td->free_struct    = asn_DEF_NativeEnumerated.free_struct;
	td->print_struct   = asn_DEF_NativeEnumerated.print_struct;
	td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
	td->ber_decoder    = asn_DEF_NativeEnumerated.ber_decoder;
	td->der_encoder    = asn_DEF_NativeEnumerated.der_encoder;
	td->xer_decoder    = asn_DEF_NativeEnumerated.xer_decoder;
	td->xer_encoder    = asn_DEF_NativeEnumerated.xer_encoder;
	td->uper_decoder   = asn_DEF_NativeEnumerated.uper_decoder;
	td->uper_encoder   = asn_DEF_NativeEnumerated.uper_encoder;
	if(!td->per_constraints)
		td->per_constraints = asn_DEF_NativeEnumerated.per_constraints;
	td->elements       = asn_DEF_NativeEnumerated.elements;
	td->elements_count = asn_DEF_NativeEnumerated.elements_count;
     /* td->specifics      = asn_DEF_NativeEnumerated.specifics;	// Defined explicitly */
}

void
EssPrecipSituation_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	EssPrecipSituation_1_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

int
EssPrecipSituation_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	EssPrecipSituation_1_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

asn_dec_rval_t
EssPrecipSituation_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	EssPrecipSituation_1_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

asn_enc_rval_t
EssPrecipSituation_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	EssPrecipSituation_1_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

asn_dec_rval_t
EssPrecipSituation_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	EssPrecipSituation_1_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

asn_enc_rval_t
EssPrecipSituation_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	EssPrecipSituation_1_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_INTEGER_enum_map_t asn_MAP_EssPrecipSituation_value2enum_1[] = {
	{ 1,	5,	"other" },
	{ 2,	7,	"unknown" },
	{ 3,	15,	"noPrecipitation" },
	{ 4,	18,	"unidentifiedSlight" },
	{ 5,	20,	"unidentifiedModerate" },
	{ 6,	17,	"unidentifiedHeavy" },
	{ 7,	10,	"snowSlight" },
	{ 8,	12,	"snowModerate" },
	{ 9,	9,	"snowHeavy" },
	{ 10,	10,	"rainSlight" },
	{ 11,	12,	"rainModerate" },
	{ 12,	9,	"rainHeavy" },
	{ 13,	25,	"frozenPrecipitationSlight" },
	{ 14,	27,	"frozenPrecipitationModerate" },
	{ 15,	24,	"frozenPrecipitationHeavy" }
};
static unsigned int asn_MAP_EssPrecipSituation_enum2value_1[] = {
	14,	/* frozenPrecipitationHeavy(15) */
	13,	/* frozenPrecipitationModerate(14) */
	12,	/* frozenPrecipitationSlight(13) */
	2,	/* noPrecipitation(3) */
	0,	/* other(1) */
	11,	/* rainHeavy(12) */
	10,	/* rainModerate(11) */
	9,	/* rainSlight(10) */
	8,	/* snowHeavy(9) */
	7,	/* snowModerate(8) */
	6,	/* snowSlight(7) */
	5,	/* unidentifiedHeavy(6) */
	4,	/* unidentifiedModerate(5) */
	3,	/* unidentifiedSlight(4) */
	1	/* unknown(2) */
};
static asn_INTEGER_specifics_t asn_SPC_EssPrecipSituation_specs_1 = {
	asn_MAP_EssPrecipSituation_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_EssPrecipSituation_enum2value_1,	/* N => "tag"; sorted by N */
	15,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_EssPrecipSituation_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_EssPrecipSituation = {
	"EssPrecipSituation",
	"EssPrecipSituation",
	EssPrecipSituation_free,
	EssPrecipSituation_print,
	EssPrecipSituation_constraint,
	EssPrecipSituation_decode_ber,
	EssPrecipSituation_encode_der,
	EssPrecipSituation_decode_xer,
	EssPrecipSituation_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_EssPrecipSituation_tags_1,
	sizeof(asn_DEF_EssPrecipSituation_tags_1)
		/sizeof(asn_DEF_EssPrecipSituation_tags_1[0]), /* 1 */
	asn_DEF_EssPrecipSituation_tags_1,	/* Same as above */
	sizeof(asn_DEF_EssPrecipSituation_tags_1)
		/sizeof(asn_DEF_EssPrecipSituation_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	0, 0,	/* Defined elsewhere */
	&asn_SPC_EssPrecipSituation_specs_1	/* Additional specs */
};

