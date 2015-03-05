/*
 * Generated by asn1c-0.9.26 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#include "ConfidenceSet.h"

#include "AccelSteerYawRateConfidence.h"
static asn_TYPE_member_t asn_MBR_ConfidenceSet_1[] = {
	{ ATF_POINTER, 6, offsetof(struct ConfidenceSet, accelConfidence),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AccelSteerYawRateConfidence,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"accelConfidence"
		},
	{ ATF_POINTER, 5, offsetof(struct ConfidenceSet, speedConfidence),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SpeedandHeadingandThrottleConfidence,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"speedConfidence"
		},
	{ ATF_POINTER, 4, offsetof(struct ConfidenceSet, timeConfidence),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeConfidence,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"timeConfidence"
		},
	{ ATF_POINTER, 3, offsetof(struct ConfidenceSet, posConfidence),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PositionConfidenceSet,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"posConfidence"
		},
	{ ATF_POINTER, 2, offsetof(struct ConfidenceSet, steerConfidence),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SteeringWheelAngleConfidence,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"steerConfidence"
		},
	{ ATF_POINTER, 1, offsetof(struct ConfidenceSet, throttleConfidence),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ThrottleConfidence,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"throttleConfidence"
		},
};
static ber_tlv_tag_t asn_DEF_ConfidenceSet_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_ConfidenceSet_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* accelConfidence */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* speedConfidence */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* timeConfidence */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* posConfidence */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* steerConfidence */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* throttleConfidence */
};
static asn_SEQUENCE_specifics_t asn_SPC_ConfidenceSet_specs_1 = {
	sizeof(struct ConfidenceSet),
	offsetof(struct ConfidenceSet, _asn_ctx),
	asn_MAP_ConfidenceSet_tag2el_1,
	6,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	5,	/* Start extensions */
	7	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_ConfidenceSet = {
	"ConfidenceSet",
	"ConfidenceSet",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_ConfidenceSet_tags_1,
	sizeof(asn_DEF_ConfidenceSet_tags_1)
		/sizeof(asn_DEF_ConfidenceSet_tags_1[0]), /* 1 */
	asn_DEF_ConfidenceSet_tags_1,	/* Same as above */
	sizeof(asn_DEF_ConfidenceSet_tags_1)
		/sizeof(asn_DEF_ConfidenceSet_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_ConfidenceSet_1,
	6,	/* Elements count */
	&asn_SPC_ConfidenceSet_specs_1	/* Additional specs */
};

