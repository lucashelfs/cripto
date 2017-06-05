/* EP de Criptografia
 * Lucas Helfstein Rocha
 * NºUSP 8802426
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <math.h>

/* Se quiser imprimir as variáveis para debug */
int debug = 1;

/* Definição de tipos */
typedef unsigned char byte_t;
typedef char * string;

/* Protótipos das funções */
int Alg_K128(uint64_t keys[], byte_t file_bytes[]);
int identificar_modo();
string concatenada(string chave_k, string entrada);
uint64_t chavePara64(string key);
uint64_t shiftEsq(uint64_t n, unsigned int d);
uint64_t shiftDir(uint64_t n, unsigned int d);
uint64_t * subchaves();

long get_file_size(char file_name[]);
void read_file_to_array(char file_name[], byte_t file_bytes[], long file_size);

int main(int argc, char ** argv){

  /* Dívida técnica: consertar intro  */
  int modo=0;
  long file_size;
  string senha, entrada, saida;

  FILE * arq_sai;
  arq_sai = fopen(saida, "a+");

  modo = identificar_modo(argv);
  entrada = malloc(sizeof(char)*(strlen(argv[3]) + 1));
  saida = malloc(sizeof(char)*(strlen(argv[5]) + 1));
  strcpy(entrada, argv[3]);
  strcpy(saida, argv[5]);

  if(modo == 1 || modo == 2){
    senha = argv[7];
    if (debug) printf("\nSenha=%s --> Bytes=%d", senha, (int)strlen(senha));
  }
  else {
    senha = argv[5];
    if (debug) printf("\nSenha=%s --> Bytes=%d", senha, (int)strlen(senha));
  }

  /* Dívida técnica: Warning pelo método como fiz abaixo*/
  string chave_k;
  chave_k = concatenada(chave_k, senha);
  if (debug) printf("\nSenha concatenada = %s \n", chave_k);

  uint64_t * sub_k;
  sub_k = subchaves(chave_k);

  byte_t * file_bytes;
  file_size = get_file_size(entrada);
  file_bytes = malloc(file_size * sizeof (*file_bytes));
  read_file_to_array(entrada, file_bytes, file_size);
  printf("\nInput size = %ld \n", file_size);

  int test_alg = Alg_K128(sub_k, file_bytes);

  free(entrada);
  free(saida);
  free(chave_k);
  free(sub_k);
  free(file_bytes);
  fclose(arq_sai);
  return 0;
}

void read_file_to_array(char file_name[], byte_t file_bytes[], long file_size) {
    FILE *p_input_file;

    p_input_file = fopen(file_name, "rb");
    if (p_input_file == NULL) {
        printf("Input file %s not found.\n", file_name);
        exit(1);
    }

    fread(file_bytes, sizeof(*file_bytes), file_size, p_input_file);
    fclose(p_input_file);
}

/* Converte uma string para uint64 */
uint64_t chavePara64(string key) {
  int i;
  uint64_t num = 0;
  num = (uint8_t)key[0];
  for (i=1;i<8;i++){
    num = num << 8;
    num |= (uint8_t)key[i];
  }
  return num;
}

/* Converter um uint64 para string */
string numParaChave(uint64_t num){
  int i;
  string chave = malloc(sizeof(char)*(8+1));
  for(i=7; i>-1; i--){
    chave[i] = num & 0x00FF;
    num = num >> 8;
  }
  chave[8] = 0;
  return chave;
}

/* Converter um uint64 para vetor de uint8_t */
uint8_t * numParaVet(uint64_t num){
  int i;
  string chave = malloc(sizeof(uint8_t)*(8));
  for(i=7; i>-1; i--){
    chave[i] = num & 0x00FF;
    num = num >> 8;
  }
  return chave;
}

uint64_t shiftEsq(uint64_t n, unsigned int d){
   /* In n<<d, ultimos d viram zero. To put first 3 bits of n at
     last, do bitwise or of n<<d with n >>(INT_BITS - d) */
   return (n << d)|(n >> (64 - d));
}

uint64_t shiftDir(uint64_t n, unsigned int d){
   /* In n>>d, first d bits are 0. To put last 3 bits of at
     first, do bitwise or of n>>d with n <<(INT_BITS - d) */
   return (n >> d)|(n << (64 - d));
}

uint64_t * subchaves(string chave_k){

  int i, j, s;
  int r = 12;
  int tam = 2 * r + 1;

  /* output para debug */
  FILE * arquivo;
  arquivo = fopen("output_subchaves", "w+");
  fputs ("key_main ",arquivo);
  for (i=0;i<16;i++) fprintf(arquivo," %c  ",chave_k[i]);
  fputs ("\nkey_hexa ",arquivo);
  for (i=0;i<16;i++) fprintf(arquivo,"%x  ",chave_k[i]);
  fputs ("\n------------ \n",arquivo);

  /* Separar a string em duas partes: apenas pra debug */
  string esq, dir, reversed;

  if (debug) {
    esq = malloc(sizeof(char)*(8+1));
    dir = malloc(sizeof(char)*(8+1));
    memcpy(esq,chave_k,8);
    memcpy(dir,chave_k+8,8);
    esq[8] = 0;
    dir[8] = 0;
  }

  uint64_t esq_val = 0;
  uint64_t dir_val = 0;
  uint64_t A;
  uint64_t B;
  uint64_t * L;
  uint64_t * k;
  L = malloc(sizeof(uint64_t)*(tam+1));
  k = malloc(sizeof(uint64_t)*(tam+1));

  /* chave_k vira um uint64 */
  esq_val = chavePara64(chave_k);
  dir_val = chavePara64(chave_k+8);

  if (debug) {
    printf("Esquerda: %s\n", esq);
    printf("Direita: %s\n", dir);
    reversed = numParaChave(esq_val);
    printf("Esquerda reversa : %s\n", reversed);
    reversed = numParaChave(dir_val);
    printf("Direita reversa : %s\n", reversed);
    printf("Valor esq (hex): %" PRIx64 "\n", esq_val);
    printf("Valor dir (hex): %" PRIx64 "\n", dir_val);
    free(esq);
    free(dir);
  }

  L[0] = esq_val;
  L[1] = dir_val;

  for (j=2;j<(tam+1); j++)
    L[j] = L[j-1] + 0x9e3779b97f4a7c15;

  k[0] = 0xb7e151628aed2a6b;

  for (j=1;j<(tam+1); j++)
    k[j] = k[j-1] + 0x7f4a7c159e3779b9;

  i=0; j=0;
  A = 0x0000000000000000;
  B = 0x0000000000000000;

  for (s=1;s<(tam+1);s++){
    k[i] = (k[i] + A + B);
    k[i] = shiftEsq(k[i], 3);
    A = k[i];
    i = i+1;
    L[j] = (L[j] + A + B);
    L[j] = shiftEsq(L[j], A + B);
    B = L[j];
    j = j+1;
  }

  /* Subkeys no arquivo */
  for (i=0;i<tam+1;i++) fprintf(arquivo,"k[%02d] = %" PRIx64 "\n", i, k[i]);
  fclose(arquivo);
  free(L);
  return k;
}

int Alg_K128(uint64_t keys[], byte_t file_bytes[]){
  int i, r, R = 12;
  uint64_t key;
  uint8_t * b;

  /* Separar os bytes da chave */
  for (r=1;r<R+1;r++){
    key = keys[(2*r) - 1];
    b = numParaVet(key);
    printf("\n");
    for (i=0;i<8;i++) printf("%" PRIx8, b[i]);
    free(b);
  }
  return 0;
}

int identificar_modo(char ** argv){
  if (strcmp(argv[1],"-c") == 0){
        printf("Criptografar! \n");
        return 1;
  }
  else if (strcmp(argv[1],"-d") == 0){
        printf("Decriptografar! \n");
        return 2;
  }
  else if (strcmp(argv[1],"-1") == 0){
        printf("Aleatoriedade 1! \n");
        return 3;
  }
  else if (strcmp(argv[1],"-2") == 0){
        printf("Aleatoriedade 2! \n");
        return 4;
  }
  return 0;
}

long get_file_size(string file_name) {
    FILE *p_input_file;
    long file_size;

    p_input_file = fopen(file_name, "rb");
    if (p_input_file == NULL) {
        printf("Input file %s not found.\n", file_name);
        exit(1);
    }

    fseek(p_input_file, 0, SEEK_END);
    file_size = ftell(p_input_file);
    fseek(p_input_file, 0, SEEK_SET);
    fclose(p_input_file);

    return file_size;
}

int identifica_entrada(char ** argv){
  if (debug) printf("Pegue o arquivo: %s! \n", argv[3]);
  return 0;
}

int identifica_saida(char ** argv){
  if (debug) printf("Jogue em: %s! \n", argv[5]);
  return 0;
}

string concatenada(string chave_k, string entrada){
  int i;
  string dest;
  dest = malloc(sizeof(char)*(240+1));
  chave_k = malloc(sizeof(char)*(16+1));
  strcpy(dest,entrada);
  for (i=0; i<16; i++) strcat(dest, entrada);
  memcpy(chave_k,dest,16);
  chave_k[16] = 0;
  free(dest);
  return chave_k;
}
