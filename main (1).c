#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include "aes.h"

bool dflag = false; //bandera encriptación/desencriptación

void print_help(char *command)
{
	printf("secret encripta o desincripta un archivo usando el algoritmo AES.\n");
	printf("uso:\n %s [-d] -k <key> <nombre_archivo>\n", command);
	printf(" %s -h\n", command);
	printf("Opciones:\n");
	printf(" -h\t\t\tAyuda, muestra este mensaje\n");
	printf(" -d\t\t\tDesincripta el archivo en lugar de encriptarlo.\n");
	printf(" -k <key>\t\tEspecifica la clave (key) de encriptación, 128-bits (16 bytes) en hex.\n");
}

int main(int argc, char **argv)
{
	struct stat mi_stat;
	char *input_file = NULL;
	char *key_arg_str = NULL;

	int opt, index;
	
	while ((opt = getopt (argc, argv, "dhk:")) != -1){
		switch(opt)
		{
			case 'd':
				dflag = true;
				break;
			case 'h':
				print_help(argv[0]);
				return 0;
			case 'k':
				key_arg_str = optarg;
        		break;
			case '?':
			default:
				fprintf(stderr, "uso: %s [-d] -k <key> <nombre_archivo>\n", argv[0]);
				fprintf(stderr, "     %s -h\n", argv[0]);
				return 1;
		}
	}

	/* Aquí recoge argumentos que no son opción, por ejemplo el nombre del input file */
	for (index = optind; index < argc; index++)
		input_file = argv[index];

	if(!input_file){
		fprintf(stderr, "Especifique el nombre del archivo.\n");
		fprintf(stderr, "uso: %s [-d] -k <key> <nombre_archivo>\n", argv[0]);
		fprintf(stderr, "     %s -h\n", argv[0]);
		return 1;
	}else{
		/* Ejemplo como verificar existencia y tamaño de un archivo */
		if(stat(input_file, &mi_stat) < 0){
			fprintf(stderr, "Archivo %s no existe!\n", input_file);
			return 1;
		}else
			printf("Leyendo el archivo %s (%ld bytes)...\n", input_file, mi_stat.st_size);
	}

	//Arreglo bytes clave de encriptación/desencriptación
	BYTE key_arg_binario[16];
	WORD key_schedule[60];

	//Buffer de encriptación/desencriptación
	BYTE aes_buffer[AES_BLOCK_SIZE];
	//Buffer de lectura, inicializado en cero
	BYTE read_buffer[AES_BLOCK_SIZE] = {0};

	/* Valida la clave de encriptación */
	if(key_arg_str){
		if(strlen(key_arg_str) != 32){
			fprintf(stderr, "Error en tamaño de la clave de encriptación.\n");
			return 1;
		}

		//Convertir clave en representación hex a binario...
		BYTE byte, i;
		for(i=0;i<16;i++){
			sscanf(key_arg_str + 2*i,"%2hhx", &byte);
			key_arg_binario[i] = byte;
		}
	}else{
		fprintf(stderr, "Error al especificar la clave de encriptación.\n");
		fprintf(stderr, "uso: %s [-d] -k <key> <nombre_archivo>\n", argv[0]);
		fprintf(stderr, "     %s -h\n", argv[0]);
		return 1;
	}

	aes_key_setup(key_arg_binario, key_schedule, 128);

	//Abrir archivo solo lectura
	int fd_read = open(input_file, O_RDONLY, 0);

	//Crear nombre archivo de salida
	char *output_file = (char *) calloc(strlen(input_file) + 5,1);
	strcpy(output_file, input_file);

	if(dflag)
		strcat(output_file, ".dec");
	else
		strcat(output_file, ".enc");

	//Crear/truncar archivo de salida con permisos de escritura y lectura para el dueño
	int fd_write = open(output_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);

	//Leer el archivo de lectura 16 bytes a la vez
	while(read(fd_read, read_buffer, AES_BLOCK_SIZE) > 0){
		if(dflag)
			aes_decrypt(read_buffer, aes_buffer, key_schedule, 128);
		else
			aes_encrypt(read_buffer, aes_buffer, key_schedule, 128);

		write(fd_write, aes_buffer, AES_BLOCK_SIZE);

		//Encerar buffer
		memset(read_buffer, 0, sizeof read_buffer);
	}

	if(dflag)
		printf("Archivo %s desencriptado exitosamente en %s...\n", input_file, output_file);
	else
		printf("Archivo %s encriptado exitosamente en %s...\n", input_file, output_file);

	free(output_file);
	close(fd_read);
	close(fd_write);

	return 0;
}
