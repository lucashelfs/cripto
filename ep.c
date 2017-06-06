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

/* Print some stuff for debug */
int debug = 1;

typedef unsigned char byte_t;
typedef char * string;

/* Functions */
void precalculate();
void Alg_K128(uint64_t keys[], byte_t file_bytes[]);
int get_mode();
string concat_passwd(string chave_k, string entrada);
uint8_t mod257(int exp);
uint8_t * iteration (int r, uint64_t keys[], byte_t file_bytes[]);
uint64_t key_to_int64(string key);
uint64_t shift_left(uint64_t n, unsigned int d);
uint64_t shift_right(uint64_t n, unsigned int d);
uint64_t * subkeys();

/* check these */
long get_file_size(char file_name[]);
void read_file_to_array(char file_name[], byte_t file_bytes[], long file_size);

/* efficience matters */
uint8_t powers[256];
uint8_t logs[256];

int main(int argc, char ** argv){

  /* Dívida técnica: consertar intro  */
  int modo=0;
  long file_size;
  string senha, entrada, saida;

  FILE * arq_sai;
  arq_sai = fopen(saida, "a+");

  modo = get_mode(argv);
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
  chave_k = concat_passwd(chave_k, senha);
  if (debug) printf("\nSenha concat_passwd = %s \n", chave_k);

  uint64_t * sub_k;
  sub_k = subkeys(chave_k);

  byte_t * file_bytes;
  file_size = get_file_size(entrada);
  file_bytes = malloc(file_size * sizeof (*file_bytes));
  read_file_to_array(entrada, file_bytes, file_size);
  printf("\nInput size = %ld \n", file_size);
  precalculate();
  Alg_K128(sub_k, file_bytes);

  free(entrada);
  free(saida);
  free(chave_k);
  free(sub_k);
  free(file_bytes);
  /*fclose(arq_sai);*/
  return 0;
}

void precalculate(){
  int aux;
  for(aux=0;aux<256;aux++){
      powers[aux] = mod257(aux);
      logs[powers[aux]] = (uint8_t) aux;
  }
    /* if (debug) for(i=0;i<256;i++) printf("exp: %3d \t y: %3d \tx: %3d \n", i, powers[i], logs[i]); */
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
uint64_t key_to_int64(string key) {
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
string number_to_key(uint64_t num){
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
uint8_t * number_to_array(uint64_t num){
  int i;
  string chave = malloc(sizeof(uint8_t)*(8));
  for(i=7; i>-1; i--){
    chave[i] = num & 0x00FF;
    num = num >> 8;
  }
  return chave;
}

uint64_t shift_left(uint64_t n, unsigned int d){
   return (n << d)|(n >> (64 - d));
}

uint64_t shift_right(uint64_t n, unsigned int d){
   return (n >> d)|(n << (64 - d));
}

uint64_t * subkeys(string chave_k){

  int i, j, s;
  int r = 12;
  int tam = 2 * r + 1;

  /* output para debug */
  FILE * arquivo;
  arquivo = fopen("output_subkeys", "w+");
  fputs ("key_main ",arquivo);
  for (i=0;i<16;i++) fprintf(arquivo," %c  ",chave_k[i]);
  fputs ("\nkey_hexa ",arquivo);
  for (i=0;i<16;i++) fprintf(arquivo,"%x  ",chave_k[i]);
  fputs ("\n------------ \n",arquivo);

  /* Separar a string em duas partes: apenas pra debug */
  string reversed;

  uint64_t esq_val = 0;
  uint64_t dir_val = 0;
  uint64_t A;
  uint64_t B;
  uint64_t * L;
  uint64_t * k;
  L = malloc(sizeof(uint64_t)*(tam+1));
  k = malloc(sizeof(uint64_t)*(tam+1));

  /* chave_k vira um uint64 */
  esq_val = key_to_int64(chave_k);
  dir_val = key_to_int64(chave_k+8);

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
    k[i] = shift_left(k[i], 3);
    A = k[i];
    i = i+1;
    L[j] = (L[j] + A + B);
    L[j] = shift_left(L[j], A + B);
    B = L[j];
    j = j+1;
  }

  /* Subkeys no arquivo */
  for (i=0;i<tam+1;i++) fprintf(arquivo,"k[%02d] = %" PRIx64 "\n", i, k[i]);
  fclose(arquivo);
  free(L);
  return k;
}

uint8_t mod257(int exp){
  int MOD = 257;
  int val = 45;
  if(exp == 0)
    return 1;
  int v = mod257(exp/2);
  if(exp % 2 == 0)
    return (v*v) % MOD;
  else
    return (((v*val) % MOD) * v) % MOD;
}

void Alg_K128(uint64_t keys[], byte_t file_bytes[]){
  int i, r, R = 12;
  uint64_t key, C[8];

  FILE * arquivo;
  arquivo = fopen("output_k128", "a+");
  fputs ("key_main ",arquivo);
/*  for (i=0;i<16;i++) fprintf(arquivo," %c  ",chave_k[i]);
  fputs ("\nkey_hexa ",arquivo); */

  /* Iterações: 12 rounds */
  /* for (r=1;r<=R;r++) iteration(r, keys, (file_bytes+(8*i))); */

  uint8_t test[] = { 0x43, 0x48, 0x3e, 0xb1, 0x8d, 0x5a, 0xdf, 0x93 };

  iteration(1, keys, test);

  /* Escrever no arquivo */
/*  for (i=0;i<tam+1;i++) fprintf(arquivo,"k[%02d] = %" PRIx64 "\n", i, k[i]);*/
  fclose(arquivo);
}

uint8_t * iteration (int r, uint64_t keys[], byte_t file_bytes[]){
  uint8_t * C = malloc(sizeof(uint8_t)*(8));
  uint8_t * mid = malloc(sizeof(uint8_t)*(8));
  uint8_t * k1 = number_to_array(keys[(2*r - 1)]);
  uint8_t * k2 = number_to_array(keys[(2*r)]);
  uint8_t * k3 = number_to_array(keys[(2*r + 1)]);

  int i;
  printf("\nDEBUG iteration: \n");
  printf("\nk_1 blocks: \t");
  for (i=0;i<8;i++){
    printf("%02"PRIx8 " ", k1[i]);
  }
  printf("\nk_2 blocks: \t");
  for (i=0;i<8;i++){
    printf("%02"PRIx8 " ", k2[i]);
  }
  printf("\nB: \t\t");
  for (i=0;i<8;i++){
    printf("%02"PRIx8 " ", file_bytes[i]);
  }
  printf("\n\n");

  /* Primeiro passo */
  C[0] = file_bytes[0] ^ k1[0];
  C[1] = file_bytes[1] + k1[1];
  C[2] = file_bytes[2] + k1[2];
  C[3] = file_bytes[3] ^ k1[3];
  C[4] = file_bytes[4] ^ k1[4];
  C[5] = file_bytes[5] + k1[5];
  C[6] = file_bytes[6] + k1[6];
  C[7] = file_bytes[7] ^ k1[7];

  printf("Parte 1: \n");
  for (i=0;i<8;i++){
    printf("%"PRIx8 " ", C[i]);
  }
  printf("\n");

  /*Segundo passo*/
  C[0] = powers[C[0]];
  C[1] = logs[C[1]];
  C[2] = logs[C[2]];
  C[3] = powers[C[3]];
  C[4] = powers[C[4]];
  C[5] = logs[C[5]];
  C[6] = logs[C[6]];
  C[7] = powers[C[7]];

  printf("Parte 2: \n");
  for (i=0;i<8;i++){
    printf("%02"PRIx8 " ", C[i]);
  }
  printf("\n");

  /*Terceiro passo*/
  C[0] = C[0] + k2[0];
  C[1] = C[1] ^ k2[1];
  C[2] = C[2] ^ k2[2];
  C[3] = C[3] + k2[3];
  C[4] = C[4] + k2[4];
  C[5] = C[5] ^ k2[5];
  C[6] = C[6] ^ k2[6];
  C[7] = C[7] + k2[7];

  printf("Parte 3: \n");
  for (i=0;i<8;i++){
    printf("%02"PRIx8 " ", C[i]);
  }
  printf("\n");

  /*Quarto passo*/
  mid[0] = (2*C[0] + C[1]) % 256;
  mid[1] = (C[0] + C[1]) % 256;

  mid[2] = (2*C[2] + C[3]) % 256;
  mid[3] = (C[2] + C[3]) % 256;

  mid[4] = (2*C[4] + C[5]) % 256;
  mid[5] = (C[4] + C[5]) % 256;

  mid[6] = (2*C[6] + C[7]) % 256;
  mid[7] = (C[6] + C[7]) % 256;

  /*Quarto - parte 2 */
  C[0] = (2*mid[0] + mid[2]) % 256;
  C[1] = (mid[0] + mid[2]) % 256;

  C[2] = (2*mid[4] + mid[6]) % 256;
  C[3] = (mid[4] + mid[6]) % 256;

  C[4] = (2*mid[1] + mid[3]) % 256;
  C[5] = (mid[1] + mid[3]) % 256;

  C[6] = (2*mid[5] + mid[7]) % 256;
  C[7] = (mid[5] + mid[7]) % 256;

  /*Quarto - parte 3 */
  mid[0] = (2*C[0] + C[2]) % 256;
  mid[1] = (C[0] + C[2]) % 256;

  mid[2] = (2*C[4] + C[6]) % 256;
  mid[3] = (C[4] + C[6]) % 256;

  mid[4] = (2*C[1] + C[3]) % 256;
  mid[5] = (C[1] + C[3]) % 256;

  mid[6] = (2*C[5] + C[7]) % 256;
  mid[7] = (C[5] + C[7]) % 256;

  printf("Parte 4: \n");
  for (i=0;i<8;i++){
    printf("%02"PRIx8 " ", mid[i]);
  }
  printf("\n");

  /* Transformação final */
  C[0] = mid[0] ^ k3[0];
  C[1] = mid[1] + k3[1];
  C[2] = mid[2] + k3[2];
  C[3] = mid[3] ^ k3[3];
  C[4] = mid[4] ^ k3[4];
  C[5] = mid[5] + k3[5];
  C[6] = mid[6] + k3[6];
  C[7] = mid[7] ^ k3[7];

  printf("\nFinal da iteração - com tranformação final: \n");
  for (i=0;i<8;i++){
    printf("%02"PRIx8 " ", C[i]);
  }
  printf("\n");

  free(k1);
  free(k2);
  free(k3);
  free(mid);
  return C;
}

int get_mode(char ** argv){
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

string concat_passwd(string chave_k, string entrada){
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
