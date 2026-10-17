// Gate Ola 12 (math): trig/hyperbolic/inverse + rounding on a real boot.
#define _GNU_SOURCE
#include <math.h>
#include <stdio.h>

static int close_enough(double a, double b)
{
	double d = a - b;
	if (d < 0)
		d = -d;
	double m = b < 0 ? -b : b;
	if (m < 1.0)
		m = 1.0;
	return d <= 1e-12 * m;
}

int main(void)
{
	if (!close_enough(sin(0.5), 0.479425538604203)) {
		printf("sin fail\n");
		return 1;
	}
	if (!close_enough(atan2(1.0, 1.0), 0.7853981633974483)) {
		printf("atan2 fail\n");
		return 1;
	}
	if (!close_enough(tanh(1.0), 0.7615941559557649)) {
		printf("tanh fail\n");
		return 1;
	}
	if (!close_enough(asinh(1.0), 0.881373587019543)) {
		printf("asinh fail\n");
		return 1;
	}
	if (floor(-2.5) != -3.0 || ceil(2.5) != 3.0 || round(2.5) != 3.0 || trunc(-2.7) != -2.0) {
		printf("rounding fail\n");
		return 1;
	}
	if (fabs(-3.0) != 3.0 || copysign(1.0, -2.0) != -1.0) {
		printf("abs fail\n");
		return 1;
	}
	if (!close_enough(sinf(0.5f), 0.47942554f)) {
		printf("sinf fail\n");
		return 1;
	}
	double s, c;
	sincos(0.5, &s, &c);
	if (!close_enough(s, 0.479425538604203) || !close_enough(c, 0.8775825618903728)) {
		printf("sincos fail\n");
		return 1;
	}
	if (!isnan(sin(INFINITY)) || !isnan(asin(2.0))) {
		printf("nan fail\n");
		return 1;
	}
	printf("math ok\n");
	return 0;
}
