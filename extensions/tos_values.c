#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/ip.h>

#ifndef IPTOS_NORMALSVC
#	define IPTOS_NORMALSVC 0
#endif

struct tos_value_mask {
	uint8_t value, mask;
};

static const struct tos_symbol_info {
	unsigned char value;
	const char *name;
} tos_symbol_names[] = {
	{IPTOS_LOWDELAY,    "Minimize-Delay"},
	{IPTOS_THROUGHPUT,  "Maximize-Throughput"},
	{IPTOS_RELIABILITY, "Maximize-Reliability"},
	{IPTOS_MINCOST,     "Minimize-Cost"},
	{IPTOS_NORMALSVC,   "Normal-Service"},
	{},
};

/*
 * tos_parse_numeric - parse sth. like "15/255"
 *
 * @str:	input string
 * @tvm:	(value/mask) tuple
 * @max:	maximum allowed value (must be pow(2,some_int)-1)
 */
static bool tos_parse_numeric(const char *str, struct tos_value_mask *tvm,
                              unsigned int max)
{
	unsigned int value;
	char *end;

	xtables_strtoui(str, &end, &value, 0, max);
	tvm->value = value;
	tvm->mask  = max;

	if (*end == '/') {
		const char *p = end + 1;

		if (!xtables_strtoui(p, &end, &value, 0, max))
			xtables_error(PARAMETER_PROBLEM, "Illegal value: \"%s\"",
			           str);
		tvm->mask = value;
	}

	if (*end != '\0')
		xtables_error(PARAMETER_PROBLEM, "Illegal value: \"%s\"", str);
	return true;
}

/**
 * @str:	input string
 * @tvm:	(value/mask) tuple
 * @def_mask:	mask to force when a symbolic name is used
 */
static bool tos_parse_symbolic(const char *str, struct tos_value_mask *tvm,
    unsigned int def_mask)
{
	static const unsigned int max = UINT8_MAX;
	const struct tos_symbol_info *symbol;
	char *tmp;

	if (xtables_strtoui(str, &tmp, NULL, 0, max))
		return tos_parse_numeric(str, tvm, max);

	/* Do not consider ECN bits when using preset names */
	tvm->mask = def_mask;
	for (symbol = tos_symbol_names; symbol->name != NULL; ++symbol)
		if (strcasecmp(str, symbol->name) == 0) {
			tvm->value = symbol->value;
			return true;
		}

	xtables_error(PARAMETER_PROBLEM, "Symbolic name \"%s\" is unknown", str);
	return false;
}

static bool tos_try_print_symbolic(const char *prefix,
    u_int8_t value, u_int8_t mask)
{
	const struct tos_symbol_info *symbol;

	if (mask != 0x3F)
		return false;

	for (symbol = tos_symbol_names; symbol->name != NULL; ++symbol)
		if (value == symbol->value) {
			printf("%s%s ", prefix, symbol->name);
			return true;
		}

	return false;
}
