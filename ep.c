/* EP de Criptografia
 * Lucas Helfstein Rocha
 * NºUSP 8802426
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Definição de tipos
typedef char * string;

// Protótipos das funções
int subchaves();
int Alg_K128();
int identificar_modo();
int identifica_entrada();
int identifica_saida();
string concatenada(string chave_k, string entrada);

// Main
int main(int argc, char ** argv){

  // Para debug
  // printf("\ncmdline args count=%d", argc);
  // printf("\nexe name=%s \n", argv[0]);
  // for (i=0; i<argc; i++) printf("%d = %s \n", i, argv[i]);

  // LER A ENTRADA
  int i=0;
  int modo;
  int entrada, saida;
  string senha;

  modo = identificar_modo(argv);
  entrada = identifica_entrada(argv);

  if(modo == 1 || modo == 2){
    saida = identifica_saida(argv);
    senha = argv[7];
    printf("\nSenha=%s --> Bytes=%d", senha, (int)strlen(senha));
  }
  else {
    senha = argv[5];
    printf("\nSenha=%s --> Bytes=%d", senha, (int)strlen(senha));
  }

  // Chave K concatenada
  string chave_k;
  chave_k = concatenada(chave_k, senha);
  printf("\nSenha concatenada = %s \n", chave_k);


  // ARQUIVOS
  // FILE *arq_entra,
  // FILE *arq_sai;
  // arq_entra = fopen(entrada, "r+");
  // arq_sai = fopen(saida, "w+");

  // Senha e chave principal K
  // A senha a ser digitada: a senha A no parametro -p <senha> deve conter pelo menos 8 caracteres, sendo A com pelo menos 2
  // letras e 2 algarismos decimais;
  // Geração da chave K de 128 bits a partir da senha: se a senha A digitada possuir menos que 16 caracteres (i.e., 16 bytes), a
  // chave K de 128 bits deve ser derivada de A concatenando-se A com ela própria até somar 16 bytes (128 bits).

  // Liberar memória e sair
  free(chave_k);
  return 0;
}
// ___  ________ _   _  _   _   ___   _____
// |  \/  |_   _| \ | || | | | / _ \ /  ___|
// | .  . | | | |  \| || |_| |/ /_\ \\ `--.
// | |\/| | | | | . ` ||  _  ||  _  | `--. \
// | |  | |_| |_| |\  || | | || | | |/\__/ /
// \_|  |_/\___/\_| \_/\_| |_/\_| |_/\____/
//
//
// ______ _   _ _   _ _____ _____ _____ _____
// |  ___| | | | \ | /  __ \  _  |  ___/  ___|
// | |_  | | | |  \| | /  \/ | | | |__ \ `--.
// |  _| | | | | . ` | |   | | | |  __| `--. \
// | |   | |_| | |\  | \__/\ \_/ / |___/\__/ /
// \_|    \___/\_| \_/\____/\___/\____/\____/
//
// Geração de subchaves
int subchaves(){
  return 0;
}
// Algoritmo K128
int Alg_K128(){
  return 0;
}
// Obtem o modo a partir da entrada
int identificar_modo(char ** argv){
  // Modo (1) Para criptografar arquivos:
  // programa -c -i <arquivo de entrada> -o <arquivo de saída> -p <senha> -a
  if (strcmp(argv[1],"-c") == 0){
        printf("Criptografar! \n");
        return 1;
  }
  //  Modo (2) Para decriptografar arquivos:
  // programa -d -i <arquivo de entrada> -o <arquivo de saída> -p <senha>
  else if (strcmp(argv[1],"-d") == 0){
        printf("Decriptografar! \n");
        return 2;
  }
  //  Modo (3) Para calcular aleatoriedade pelo método 1 (item 1 abaixo):
  // programa -1 -i <arquivo de entrada> -p <senha>
  else if (strcmp(argv[1],"-1") == 0){
        printf("Aleatoriedade 1! \n");
        return 3;
  }
  //  Modo (4) Para calcular aleatoriedade pelo método 2 (item 2 abaixo):
  // programa -2 -i <arquivo de entrada> -p <senha>
  else if (strcmp(argv[1],"-2") == 0){
        printf("Aleatoriedade 2! \n");
        return 4;
  }
}
// Pega o nome do arquivo de entrada
int identifica_entrada(char ** argv){
  printf("Pegue o arquivo: %s! \n", argv[3]);
  return 0;
}
// Pega o nome do arquivo de saída
int identifica_saida(char ** argv){
  printf("Jogue em: %s! \n", argv[5]);
  return 0;
}
// Retorna a chave_k concatenada
string concatenada(string chave_k, string entrada){
  int i;
  string dest;
  dest = malloc(sizeof(char)*(240+1));
  chave_k = malloc(sizeof(char)*(16+1));
  strcpy(dest, entrada);
  for (i=0; i<16; i++) strcat(dest, entrada);
  memcpy(chave_k,dest,16);
  chave_k[16] = 0;
  free(dest);
  return chave_k;
}
