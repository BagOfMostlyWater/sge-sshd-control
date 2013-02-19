all:
	gcc -fPIC -o pam_sge-qrsh-setup.so -shared pam_sge-qrsh-setup.c
