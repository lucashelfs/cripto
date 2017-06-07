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
void        precalculate();
void        alg_k128(uint64_t keys[], byte_t file_bytes[]);

void        alg_k128_first_step(uint8_t C[], uint8_t B[], uint8_t k[]);
void        alg_k128_second_step(uint8_t C[]);
void        alg_k128_third_step(uint8_t C[], uint8_t k[]);
void        alg_k128_fourth_step(uint8_t C[]);

void        alg_k128_reverse_first_step(uint8_t C[], uint8_t B[], uint8_t k[]);
void        alg_k128_reverse_second_step(uint8_t C[]);
void        alg_k128_reverse_third_step(uint8_t C[], uint8_t k[]);
void        alg_k128_reverse_fourth_step(uint8_t C[]);

void        iteration (int r, uint64_t keys[], byte_t file_bytes[]);
void        decript_iteration (int r, uint64_t keys[], byte_t file_bytes[]);
int         get_mode();
string      concat_passwd(string chave_k, string input);
uint8_t     mod257(int exp);
uint64_t    key_to_int64(string key);
uint64_t    shift_left(uint64_t n, unsigned int d);
uint64_t    shift_right(uint64_t n, unsigned int d);
uint64_t *  subkeys();

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
  string senha, input, output;

  /*
  FILE * arq_sai;
  arq_sai = fopen(output, "a+");
  */

  modo = get_mode(argv);
  input = malloc(sizeof(char)*(strlen(argv[3]) + 1));
  output = malloc(sizeof(char)*(strlen(argv[5]) + 1));
  strcpy(input, argv[3]);
  strcpy(output, argv[5]);

  if(modo == 1 || modo == 2){
    senha = argv[7];
    if (debug) printf("\nSenha=%s --> Bytes=%d", senha, (int)strlen(senha));
  }
  else {
    senha = argv[5];
    if (debug) printf("\nSenha=%s --> Bytes=%d", senha, (int)strlen(senha));
  }

  /* Dívida técnica: Warning pelo método como fiz abaixo */
  string chave_k;
  chave_k = concat_passwd(chave_k, senha);
  if (debug) printf("\nSenha concat_passwd = %s \n", chave_k);

  uint64_t * sub_k;
  sub_k = subkeys(chave_k);

  byte_t * file_bytes;
  file_size = get_file_size(input);
  file_bytes = malloc(file_size * sizeof (*file_bytes));
  read_file_to_array(input, file_bytes, file_size);
  printf("\nInput size = %ld \n", file_size);
  precalculate();
  alg_k128(sub_k, file_bytes);

  free(input);
  free(output);
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
  /*if (debug) {
    int i;
    FILE * arquivo;
    arquivo = fopen("./outputs/output_logs_potencias", "w+");
    for(i=0;i<256;i++) fprintf(arquivo, "exp: %3d \t y: %3d \tx: %3d \n", i, powers[i], logs[i]);
    fclose(arquivo);
  }*/
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

uint8_t * number_to_array(uint64_t num){
  int i;
  uint8_t * arr = malloc(sizeof(uint8_t)*(8));
  for(i=7; i>-1; i--){
    arr[i] = num & 0x00FF;
    num = num >> 8;
  }
  return arr;
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
  arquivo = fopen("./outputs/output_subkeys", "w+");
  fputs ("key_main ",arquivo);
  for (i=0;i<16;i++) fprintf(arquivo," %c  ",chave_k[i]);
  fputs ("\nkey_hexa ",arquivo);
  for (i=0;i<16;i++) fprintf(arquivo,"%x  ",chave_k[i]);
  fputs ("\n------------ \n",arquivo);

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

  for (s=0;s<(tam+1);s++){
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

void inverse_HT2(uint8_t C[], uint8_t aux[]){
  int i;
  uint64_t a1, a2;

  for (i=0;i<8;i=i+2){

    if (C[i] < C[i+1])  a1 = C[i] + 256;
    else                a1 = C[i];

    if (C[i+1] < a1)    a2 = C[i+1] + 256;
    else                a2 = C[i+1];

    a1 = a1 - C[i+1];
    a2 = a2 - a1;

    aux[i] = a1;
    aux[i+1] = a2;
  }
}

void alg_k128_first_step(uint8_t C[], uint8_t B[], uint8_t k[]){ /* tested */
  C[0] = B[0] ^ k[0];
  C[1] = B[1] + k[1];
  C[2] = B[2] + k[2];
  C[3] = B[3] ^ k[3];
  C[4] = B[4] ^ k[4];
  C[5] = B[5] + k[5];
  C[6] = B[6] + k[6];
  C[7] = B[7] ^ k[7];

  if (debug){
    int i;
    printf("Parte 1: ");
    for (i=0;i<8;i++) printf("%02"PRIx8 " ", C[i]);
    printf("\n");
  }
}

void alg_k128_reverse_first_step(uint8_t C[], uint8_t B[], uint8_t k[]){ /* tested */
  C[0] = B[0] ^ k[0];
  C[1] = B[1] - k[1];
  C[2] = B[2] - k[2];
  C[3] = B[3] ^ k[3];
  C[4] = B[4] ^ k[4];
  C[5] = B[5] - k[5];
  C[6] = B[6] - k[6];
  C[7] = B[7] ^ k[7];

  if (debug){
    int i;
    printf("Parte 1: ");
    for (i=0;i<8;i++){
      printf("%02"PRIx8 " ", C[i]);
    }
    printf("\n");
  }
}

void alg_k128_second_step(uint8_t C[]){/* tested */
  C[0] = powers[C[0]];
  C[1] = logs[C[1]];
  C[2] = logs[C[2]];
  C[3] = powers[C[3]];
  C[4] = powers[C[4]];
  C[5] = logs[C[5]];
  C[6] = logs[C[6]];
  C[7] = powers[C[7]];

  if (debug){
    int i;
    printf("Parte 2: ");
    for (i=0;i<8;i++) printf("%02"PRIx8 " ", C[i]);
    printf("\n");
  }
}

void alg_k128_reverse_second_step(uint8_t C[]){ /* tested */
  C[0] = logs[C[0]];
  C[1] = powers[C[1]];
  C[2] = powers[C[2]];
  C[3] = logs[C[3]];
  C[4] = logs[C[4]];
  C[5] = powers[C[5]];
  C[6] = powers[C[6]];
  C[7] = logs[C[7]];

  if (debug){
    int i;
    printf("Parte 2: ");
    for (i=0;i<8;i++){
      printf("%02"PRIx8 " ", C[i]);
    }
    printf("\n");
  }
}

void alg_k128_third_step(uint8_t C[], uint8_t k[]){/* tested */
  C[0] = C[0] + k[0];
  C[1] = C[1] ^ k[1];
  C[2] = C[2] ^ k[2];
  C[3] = C[3] + k[3];
  C[4] = C[4] + k[4];
  C[5] = C[5] ^ k[5];
  C[6] = C[6] ^ k[6];
  C[7] = C[7] + k[7];

  if (debug){
    int i;
    printf("Parte 3: ");
    for (i=0;i<8;i++) printf("%02"PRIx8 " ", C[i]);
    printf("\n");
  }
}

void alg_k128_reverse_third_step(uint8_t C[], uint8_t k[]){
  C[0] = C[0] - k[0];
  C[1] = C[1] ^ k[1];
  C[2] = C[2] ^ k[2];
  C[3] = C[3] - k[3];
  C[4] = C[4] - k[4];
  C[5] = C[5] ^ k[5];
  C[6] = C[6] ^ k[6];
  C[7] = C[7] - k[7];

  if (debug){
    int i;
    printf("Parte 3: ");
    for (i=0;i<8;i++){
      printf("%02"PRIx8 " ", C[i]);
    }
    printf("\n");
  }
}

void alg_k128_fourth_step(uint8_t C[]){

  uint8_t * aux = malloc(sizeof(uint8_t)*(8));

  /* first block */
  aux[0] = (2*C[0] + C[1]) % 256;
  aux[1] = (C[0] + C[1]) % 256;
  aux[2] = (2*C[2] + C[3]) % 256;
  aux[3] = (C[2] + C[3]) % 256;
  aux[4] = (2*C[4] + C[5]) % 256;
  aux[5] = (C[4] + C[5]) % 256;
  aux[6] = (2*C[6] + C[7]) % 256;
  aux[7] = (C[6] + C[7]) % 256;

  /* second block*/
  C[0] = (2*aux[0] + aux[2]) % 256;
  C[1] = (aux[0] + aux[2]) % 256;
  C[2] = (2*aux[4] + aux[6]) % 256;
  C[3] = (aux[4] + aux[6]) % 256;
  C[4] = (2*aux[1] + aux[3]) % 256;
  C[5] = (aux[1] + aux[3]) % 256;
  C[6] = (2*aux[5] + aux[7]) % 256;
  C[7] = (aux[5] + aux[7]) % 256;

  /* third_block */
  aux[0] = (2*C[0] + C[2]) % 256;
  aux[1] = (C[0] + C[2]) % 256;
  aux[2] = (2*C[4] + C[6]) % 256;
  aux[3] = (C[4] + C[6]) % 256;
  aux[4] = (2*C[1] + C[3]) % 256;
  aux[5] = (C[1] + C[3]) % 256;
  aux[6] = (2*C[5] + C[7]) % 256;
  aux[7] = (C[5] + C[7]) % 256;

  int i;
  for (i=0; i<8; i++) C[i] = aux[i];
  free(aux);

  if (debug){
    printf("Parte 4: ");
    for (i=0;i<8;i++){
      printf("%02"PRIx8 " ", C[i]);
    }
    printf("\n");
  }
}

void alg_k128_reverse_fourth_step(uint8_t C[]){

  uint8_t * aux = malloc(sizeof(uint8_t)*(8));

  int i;

  /* reverse first_block */
  inverse_HT2(C, aux);

  C[0] = aux[0];
  C[1] = aux[4];
  C[2] = aux[1];
  C[3] = aux[5];
  C[4] = aux[2];
  C[5] = aux[6];
  C[6] = aux[3];
  C[7] = aux[7];

  /* reverse second_block*/
  inverse_HT2(C, aux);

  C[0] = aux[0];
  C[1] = aux[4];
  C[2] = aux[1];
  C[3] = aux[5];
  C[4] = aux[2];
  C[5] = aux[6];
  C[6] = aux[3];
  C[7] = aux[7];

  /* reverse first_block*/
  inverse_HT2(C, aux);
  for (i=0; i<8; i++) C[i] = aux[i];

  free(aux);

  if (debug){
    printf("Parte 4: ");
    for (i=0;i<8;i++){
      printf("%02"PRIx8 " ", C[i]);
    }
    printf("\n");
  }
}

void alg_k128(uint64_t keys[], byte_t file_bytes[]){
  int i, r, R = 12;
  uint64_t key, C[8];

/* DEBUG STUFF NOT CURRENTLY BEING USED
  FILE * arquivo;
  arquivo = fopen("./outputs/output_k128", "a+");
  fputs ("key_main ",arquivo);
  for (i=0;i<16;i++) fprintf(arquivo," %c  ",chave_k[i]);
  fputs ("\nkey_hexa ",arquivo);
  for (i=0;i<tam+1;i++) fprintf(arquivo,"k[%02d] = %" PRIx64 "\n", i, k[i]);
  fclose(arquivo);
*/

  /* Cada bloco precisa passar por 12 rouds! */
  /* Iterações: 12 rounds */
  /* for (r=1;r<=R;r++) iteration(r, keys, (file_bytes+(8*i))); */

  /* Transformação final */
/*
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
*/

  /* Testing iteration and decript_iteration */
  uint8_t test[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x48, 0x3e, 0xb1, 0x8d, 0x5a, 0xdf, 0x93 };
  iteration(1, keys, test+8);
  decript_iteration(1, keys, test+8);
}

/* Duvida: Deveria ser feito diretamente em file_bytes? */
void iteration (int r, uint64_t keys[], byte_t file_bytes[]){
  uint8_t * k1 = number_to_array(keys[(2*r - 1)]);
  uint8_t * k2 = number_to_array(keys[(2*r)]);

  if (debug){
    int i;
    printf("\nDEBUG iteration: \n");
    printf("\nk_1 blocks: \t"); for (i=0;i<8;i++) printf("%02"PRIx8 " ", k1[i]);
    printf("\nk_2 blocks: \t"); for (i=0;i<8;i++) printf("%02"PRIx8 " ", k2[i]);
    printf("\nB: \t\t"); for (i=0;i<8;i++) printf("%02"PRIx8 " ", file_bytes[i]);
    printf("\n\n");
  }

  /* etapas do algoritmo */
  alg_k128_first_step(file_bytes, file_bytes, k1);
  alg_k128_second_step(file_bytes);
  alg_k128_third_step(file_bytes, k2);
  alg_k128_fourth_step(file_bytes);

  /* evitar leaks */
  free(k1);
  free(k2);
}

void decript_iteration (int r, uint64_t keys[], byte_t file_bytes[]){
  uint8_t * k1 = number_to_array(keys[(2*r - 1)]);
  uint8_t * k2 = number_to_array(keys[(2*r)]);

  if (debug){
    int i;
    printf("\nDEBUG decript_iteration: \n");
    printf("\nk_1 blocks: \t"); for (i=0;i<8;i++) printf("%02"PRIx8 " ", k1[i]);
    printf("\nk_2 blocks: \t"); for (i=0;i<8;i++) printf("%02"PRIx8 " ", k2[i]);
    printf("\nB: \t\t"); for (i=0;i<8;i++) printf("%02"PRIx8 " ", file_bytes[i]);
    printf("\n\n");
  }

  /* etapas do algoritmo */
  alg_k128_reverse_fourth_step(file_bytes);
  alg_k128_reverse_third_step(file_bytes, k2);
  alg_k128_reverse_second_step(file_bytes);
  alg_k128_reverse_first_step(file_bytes, file_bytes, k1);

  /* evitar leaks */
  free(k1);
  free(k2);
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

int identifica_input(char ** argv){
  if (debug) printf("Pegue o arquivo: %s! \n", argv[3]);
  return 0;
}

int identifica_output(char ** argv){
  if (debug) printf("Jogue em: %s! \n", argv[5]);
  return 0;
}

string concat_passwd(string chave_k, string input){
  int i;
  string dest;
  dest = malloc(sizeof(char)*(240+1));
  chave_k = malloc(sizeof(char)*(16+1));
  strcpy(dest,input);
  for (i=0; i<16; i++) strcat(dest, input);
  memcpy(chave_k,dest,16);
  chave_k[16] = 0;
  free(dest);
  return chave_k;
}
