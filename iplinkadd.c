#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <nlinline.h>

int main(int argc, char *argv[]) {
	int rv;
	if (argc < 3) {
		fprintf(stderr, "Usage %s name type [data]\n", argv[0]);
		fprintf(stderr, "e.g.:\n" 
				            "   %s vde1 vde vxvde://\n\n", argv[0]);
		return 2;
	}
	rv = nlinline_iplink_add(argv[1], -1, argv[2], argv[3]);
	if (rv == -1)
		perror("link add");
	return 0;
}

