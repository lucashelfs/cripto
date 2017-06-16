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

/* Typedefs */
typedef unsigned char byte_t;
typedef char * string;

/* functions of the algorithm */
void        f_k128_CBC(uint64_t keys[], byte_t file_bytes[], byte_t Yj[], int blocks);
void        f_k128_CBC_reverse(uint64_t keys[], byte_t file_bytes[], byte_t Yj[], int blocks);

void        alg_k128(uint64_t keys[], byte_t file_bytes[]);
void        alg_k128_reverse(uint64_t keys[], byte_t file_bytes[]);

void        alg_k128_first_step(uint8_t C[], uint8_t B[], uint8_t k[]);
void        alg_k128_second_step(uint8_t C[]);
void        alg_k128_third_step(uint8_t C[], uint8_t k[]);
void        alg_k128_fourth_step(uint8_t C[]);
void        alg_k128_final_transformation(uint8_t C[], uint8_t k[]);

void        alg_k128_reverse_first_step(uint8_t C[], uint8_t B[], uint8_t k[]);
void        alg_k128_reverse_second_step(uint8_t C[]);
void        alg_k128_reverse_third_step(uint8_t C[], uint8_t k[]);
void        alg_k128_reverse_fourth_step(uint8_t C[]);
void        alg_k128_reverse_final_transformation(uint8_t C[], uint8_t k[]);
void        alg_k128_iteration(int r, uint64_t keys[], byte_t file_bytes[]);
void        alg_k128_decript_iteration(int r, uint64_t keys[], byte_t file_bytes[]);

uint8_t     mod257(int exp);
uint64_t    key_to_int64(char key[]);
uint64_t    shift_left(uint64_t n, unsigned int d);
uint64_t    shift_right(uint64_t n, unsigned int d);

/* hamming related */
int hamming_distance(byte_t a[], byte_t b[], int j);
int count_hamming(uint8_t a, uint8_t b);
void toggle_bit(byte_t file_bytes[], int index_of_bit);

/* manipulating files */
long        get_file_size(char file_name[]);
void        read_file_to_array(char file_name[], byte_t file_bytes[], long file_size);
void        write_array_to_file(char file_name[], byte_t file_bytes[], long file_size);
void        delete_file(char file_name[], long file_size);

/* sizes and bytes vector related */
void        fill_with_ones(byte_t file_bytes[], int begin, long end);
void        append_size_to_end_of_file(byte_t file_bytes[], int blocks, long file_size);
long        get_size_from_end_of_file(byte_t file_bytes[], int blocks);

/* major functions */
int         validate_password(char password[]);
void        sixteen_bytes_password(char key[]);
void        precalculate_values();
void        encrypt(char input_file[], char output_file[], char password[], uint64_t subkeys[]);
void        decrypt(char input_file[], char output_file[], char password[], uint64_t subkeys[]);
void        random_1(char input_file[], char password[], uint64_t subkeys[]);
void        random_2(char input_file[], char password[], uint64_t subkeys[]);
uint64_t *  subkeys();

/* global arrays with values */
uint8_t powers[256];
uint8_t logs[256];

int main(int argc, char ** argv){

  int i, modo=0, delete=0;
  char password[256];
  string input, output;
  uint64_t * sub_k;

  for(i=0; i<argc; i++){
    if (strcmp(argv[i],"-c") == 0){
      printf("Criptografar! \n");
      modo = 1;
    }
    else if (strcmp(argv[i],"-d") == 0){
      printf("Decriptografar! \n");
      modo = 2;
      }
    else if (strcmp(argv[i],"-1") == 0){
      printf("Aleatoriedade 1! \n");
      modo = 3;
    }
    else if (strcmp(argv[i],"-2") == 0){
      printf("Aleatoriedade 2! \n");
      modo = 4;
    }
    else if (strcmp(argv[i],"-a") == 0){
      printf("O arquivo será apagado! \n");
      delete = 1;
    }
    else if (strcmp(argv[i],"-p") == 0){
      strcpy(password, argv[i+1]);
      i++;
    }
    else if (strcmp(argv[i],"-i") == 0){
      input = malloc(sizeof(char)*(strlen(argv[i+1]) + 1));
      strcpy(input, argv[i+1]);
      i++;
    }
    else if (strcmp(argv[i],"-o") == 0){
      output = malloc(sizeof(char)*(strlen(argv[i+1]) + 1));
      strcpy(output, argv[i+1]);
      i++;
    }
  }

  if (!validate_password(password)){
    printf("Senha inválida!\n");
    return -1;
  }

  else {

    sixteen_bytes_password(password);
    sub_k = subkeys(password);
    precalculate_values();

    if (modo == 1) encrypt(input, output, password, sub_k);
    else if (modo == 2) decrypt(input, output, password, sub_k);
    else if (modo == 3) random_1(input, password, sub_k);
    else if (modo == 4) random_2(input, password, sub_k);

    if (delete){
      long file_size = get_file_size(input);
      delete_file(input, file_size);
    }

  }

  free(sub_k);
  printf("Operação finalizada.\n");
  return 0;
}

int validate_password(char password[]){
  int i, algs=0, chars=0;

  if(strlen(password)<8) return 0;

  for (i=0; i<strlen(password); i++){
    if (isalpha(password[i]))       chars++;
    else if (isdigit(password[i]))  algs++;
  }

  if(chars<2 || algs<2)  return 0;

  return 1;
}

void sixteen_bytes_password(char key[]){

  if (strlen(key) >= 16) return;
  else {
    if(strlen(key) <= 8){
      strcat(key, key);
      sixteen_bytes_password(key);
    }
    else strncat(key,key, 16 - strlen(key));
  }
}

void encrypt(char input_file[], char output_file[], char password[], uint64_t subkeys[]){

  int num_of_blocks;
  long file_size;
  byte_t * file_bytes;

  uint8_t CBC[8] = {1, 1, 1, 1, 1, 1, 1, 1};

  /* number of bytes */
  file_size = get_file_size(input_file);

  if ((int) file_size % 8 == 0)  num_of_blocks = (int) (file_size / 8);
  else                           num_of_blocks = (int) (file_size / 8) + 1;

  num_of_blocks = num_of_blocks + 1;
  file_bytes = malloc((num_of_blocks * 8 ) * sizeof (*file_bytes));

  /* read file */
  read_file_to_array(input_file, file_bytes, file_size);

  /* fill with ones */
  fill_with_ones(file_bytes, file_size, (num_of_blocks * 8 - 8));

  /* size of files */
  append_size_to_end_of_file(file_bytes, num_of_blocks, file_size);

  /* encrypt */
  f_k128_CBC(subkeys, file_bytes, CBC, num_of_blocks);

  /* write output */
  write_array_to_file(output_file, file_bytes, (num_of_blocks * 8));

  /* avoid leaks */
  free(file_bytes);
}

void decrypt(char input_file[], char output_file[], char password[], uint64_t subkeys[]){

  int num_of_blocks;
  long file_size;
  long original_size;
  byte_t * file_bytes;

  uint8_t CBC[8] = {1, 1, 1, 1, 1, 1, 1, 1};

  file_size = get_file_size(input_file);
  num_of_blocks = (int) (file_size / 8);

  file_bytes = malloc((num_of_blocks * 8) * sizeof (*file_bytes));

  read_file_to_array(input_file, file_bytes, file_size);

  f_k128_CBC_reverse(subkeys, file_bytes, CBC, num_of_blocks);

  original_size = get_size_from_end_of_file(file_bytes, num_of_blocks);

  write_array_to_file(output_file, file_bytes, original_size);

  free(file_bytes);
}

void random_1(char input_file[], char password[], uint64_t subkeys[]){

  int i, num_of_blocks;
  long file_size;
  byte_t * file_bytes;
  byte_t * file_bytes_changed;

  uint8_t CBC[8] = {1, 1, 1, 1, 1, 1, 1, 1};

  file_size = get_file_size(input_file);

  if ((int) file_size % 8 == 0)  num_of_blocks = (int) (file_size / 8);
  else                           num_of_blocks = (int) (file_size / 8) + 1;

  num_of_blocks = num_of_blocks + 1;


  file_bytes = malloc((num_of_blocks * 8 ) * sizeof (*file_bytes));
  file_bytes_changed = malloc((num_of_blocks * 8 ) * sizeof (*file_bytes));

  read_file_to_array(input_file, file_bytes, file_size);
  read_file_to_array(input_file, file_bytes_changed, file_size);

  num_of_blocks--;
  float H[num_of_blocks];
  float MAXS[num_of_blocks];
  float MINS[num_of_blocks];

  for(i=0; i<num_of_blocks; i++){
    H[i]    = 0;
    MAXS[i] = 0;
    MINS[i] = 100000;
  }

  f_k128_CBC(subkeys, file_bytes, CBC, num_of_blocks);

  int j, k, distance;
  int number_of_bits = 64 * num_of_blocks;

  /* alterar cada e bit e fazer as paradas */
  for(i=0; i<number_of_bits; i++){

    uint8_t CBC_encrypt[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint8_t CBC_decrypt[8] = {1, 1, 1, 1, 1, 1, 1, 1};

    toggle_bit(file_bytes_changed, i);

    f_k128_CBC(subkeys, file_bytes_changed, CBC_encrypt, num_of_blocks);

    for(k=0; k<num_of_blocks; k++){
      distance = hamming_distance(file_bytes, file_bytes_changed, k*8);
      H[k] += distance;
      if(distance<MINS[k]) MINS[k] = distance;
      if(distance>MAXS[k]) MAXS[k] = distance;
    }

    f_k128_CBC_reverse(subkeys, file_bytes_changed, CBC_decrypt, num_of_blocks);

    toggle_bit(file_bytes_changed, i);
  }

  printf("Medidas de aleatoriedade: \n");
  for(j=0; j<num_of_blocks; j++){
    printf("SumH [%3d] = %.3f \t\t", j, H[j]);
    printf("MeanH[%3d] = %.3f \t\t", j, (H[j] / ((j+1) * 64)));
    printf("MaxH [%3d] = %.3f \t\t", j, MAXS[j]);
    printf("MinH [%3d] = %.3f \t\t", j, MINS[j]);
    printf("\n");
  }

  free(file_bytes);
  free(file_bytes_changed);
}

void random_2(char input_file[], char password[], uint64_t subkeys[]){

  int i, num_of_blocks;
  long file_size;
  byte_t * file_bytes;
  byte_t * file_bytes_changed;

  uint8_t CBC[8] = {1, 1, 1, 1, 1, 1, 1, 1};

  file_size = get_file_size(input_file);

  if ((int) file_size % 8 == 0)  num_of_blocks = (int) (file_size / 8);
  else                           num_of_blocks = (int) (file_size / 8) + 1;

  num_of_blocks = num_of_blocks + 1;

  file_bytes = malloc((num_of_blocks * 8 ) * sizeof (*file_bytes));
  file_bytes_changed = malloc((num_of_blocks * 8 ) * sizeof (*file_bytes));

  read_file_to_array(input_file, file_bytes, file_size);
  read_file_to_array(input_file, file_bytes_changed, file_size);

  num_of_blocks--;
  float H[num_of_blocks];
  float MAXS[num_of_blocks];
  float MINS[num_of_blocks];

  for(i=0; i<num_of_blocks; i++){
    H[i]    = 0;
    MAXS[i] = 0;
    MINS[i] = 100000;
  }

  f_k128_CBC(subkeys, file_bytes, CBC, num_of_blocks);

  int j, k, distance;
  int number_of_bits = 64 * num_of_blocks;

  for(i=0; i<number_of_bits; i++){

    uint8_t CBC_encrypt[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint8_t CBC_decrypt[8] = {1, 1, 1, 1, 1, 1, 1, 1};

    toggle_bit(file_bytes_changed, i);
    if (i+8 < number_of_bits) toggle_bit(file_bytes_changed, i+8);

    f_k128_CBC(subkeys, file_bytes_changed, CBC_encrypt, num_of_blocks);

    for(k=0; k<num_of_blocks; k++){
      distance = hamming_distance(file_bytes, file_bytes_changed, k*8);
      H[k] += distance;
      if(distance<MINS[k]) MINS[k] = distance;
      if(distance>MAXS[k]) MAXS[k] = distance;
    }

    f_k128_CBC_reverse(subkeys, file_bytes_changed, CBC_decrypt, num_of_blocks);

    toggle_bit(file_bytes_changed, i);
    if (i+8 < number_of_bits) toggle_bit(file_bytes_changed, i+8);

  }

  printf("Medidas de aleatoriedade: \n");
  for (j=0; j<num_of_blocks; j++){
    printf("SumH [%3d] = %.3f \t\t", j, H[j]);
    printf("MeanH[%3d] = %.3f \t\t", j, (H[j] / ((j+1) * 64)));
    printf("MaxH [%3d] = %.3f \t\t", j, MAXS[j]);
    printf("MinH [%3d] = %.3f \t\t", j, MINS[j]);
    printf("\n");
  }

  free(file_bytes);
  free(file_bytes_changed);
}

int hamming_distance(byte_t a[], byte_t b[], int j){

  int i, ham = 0;
  byte_t A[8], B[8];

  A[0] = a[j + 0];
  A[1] = a[j + 1];
  A[2] = a[j + 2];
  A[3] = a[j + 3];
  A[4] = a[j + 4];
  A[5] = a[j + 5];
  A[6] = a[j + 6];
  A[7] = a[j + 7];

  B[0] = b[j + 0];
  B[1] = b[j + 1];
  B[2] = b[j + 2];
  B[3] = b[j + 3];
  B[4] = b[j + 4];
  B[5] = b[j + 5];
  B[6] = b[j + 6];
  B[7] = b[j + 7];

  for(i=0; i<8; ++i) ham += count_hamming(A[i], B[i]);

  return ham;
}

int count_hamming(uint8_t a, uint8_t b){

  int i, count=0;

  for(i=0; i<8; i++){

    if((a&1) != (b&1)) count++;

    a >>= 1;
    b >>= 1;

    }
  return count;
}

void delete_file(char file_name[], long file_size){

    FILE * p_output_file;
    byte_t * zero_array;

    p_output_file = fopen(file_name, "w+");
    zero_array = calloc(file_size, sizeof(*zero_array));
    fwrite(zero_array, sizeof(*zero_array), file_size, p_output_file);
    fclose(p_output_file);
    remove(file_name);
    free(zero_array);
}

void toggle_bit(byte_t file_bytes[], int index_of_bit){

  int index_on_number = index_of_bit % 8;
  int index_on_file_bytes = index_of_bit / 8;
  byte_t number = file_bytes[index_on_file_bytes];

  number ^= 1 << (7 - index_on_number);

  file_bytes[index_on_file_bytes] = number;
}

long get_file_size(char file_name[]){
    FILE * p_input_file;
    long file_size;

    p_input_file = fopen(file_name, "rb");

    if (p_input_file == NULL){
        printf("Input file %s not found.\n", file_name);
        exit(1);
    }

    fseek(p_input_file, 0, SEEK_END);
    file_size = ftell(p_input_file);
    fseek(p_input_file, 0, SEEK_SET);
    fclose(p_input_file);

    return file_size;
}

void read_file_to_array(char file_name[], byte_t file_bytes[], long file_size){

    FILE *p_input_file;
    p_input_file = fopen(file_name, "rb");

    if (p_input_file == NULL){
        printf("Input file %s not found.\n", file_name);
        exit(1);
    }

    fread(file_bytes, sizeof(*file_bytes), file_size, p_input_file);
    fclose(p_input_file);
}

void write_array_to_file(char file_name[], byte_t file_bytes[], long file_size){

  FILE * p_output_file;
  p_output_file = fopen(file_name, "w+");

  fwrite(file_bytes, sizeof(*file_bytes), file_size, p_output_file);
  fclose(p_output_file);
}

void fill_with_ones(byte_t file_bytes[], int begin, long end){

  int i;

  for(i=begin; i<end; i++) file_bytes[i] = 255;
}

void append_size_to_end_of_file(byte_t file_bytes[], int blocks, long file_size){

  int end = (blocks-1) * 8;

  file_bytes[end + 0] = 0;
  file_bytes[end + 1] = 0;
  file_bytes[end + 2] = 0;
  file_bytes[end + 3] = 0;
  file_bytes[end + 4] = (byte_t)((file_size & 0xFF000000) >> 24 );
  file_bytes[end + 5] = (byte_t)((file_size & 0x00FF0000) >> 16 );
  file_bytes[end + 6] = (byte_t)((file_size & 0x0000FF00) >> 8 );
  file_bytes[end + 7] = (byte_t)((file_size & 0X000000FF));
}

long get_size_from_end_of_file(byte_t file_bytes[], int blocks){

  int end = (blocks-1) * 8 + 4;
  long num=0;

  num  = ((unsigned int) file_bytes[end + 0]) << 24;
  num |= ((unsigned int) file_bytes[end + 1]) << 16;
  num |= ((unsigned int) file_bytes[end + 2]) << 8;
  num |= ((unsigned int) file_bytes[end + 3]);

  return num;
}

uint64_t key_to_int64(char key[]){

  int i;
  uint64_t num = 0;
  num = (uint8_t)key[0];

  for(i=1; i<8; i++){
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

uint64_t * subkeys(char chave_k[]){

  int i, j, s;
  int r = 12;
  int tam = 2 * r + 1;

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

  for(j=2; j<(tam+1); j++)
    L[j] = L[j-1] + 0x9e3779b97f4a7c15;

  k[0] = 0xb7e151628aed2a6b;

  for(j=1; j<(tam+1); j++)
    k[j] = k[j-1] + 0x7f4a7c159e3779b9;

  i=0; j=0;
  A = 0x0000000000000000;
  B = 0x0000000000000000;

  for(s=0; s<(tam+1); s++){
    k[i] = (k[i] + A + B);
    k[i] = shift_left(k[i], 3);
    A = k[i];
    i = i+1;
    L[j] = (L[j] + A + B);
    L[j] = shift_left(L[j], A + B);
    B = L[j];
    j = j+1;
  }

  free(L);
  return k;
}

uint8_t mod257(int exp){

  int n = 257;
  int a = 45;
  long num = 1, y = a;

  while (exp > 0){
    if (exp % 2 == 1) num = (num * y) % n;
    y = (y * y) % n;
    exp /= 2;
  }

  return (uint8_t) num % n;
}

void precalculate_values(){

  int aux;

  for(aux=0; aux<256; aux++){
      powers[aux] = mod257(aux);
      logs[powers[aux]] = (uint8_t) aux;
  }
}

void inverse_HT2(uint8_t C[], uint8_t aux[]){

  int i;
  uint8_t a1, a2;

  for(i=0;i<8;i=i+2){

    a1 = C[i] - C[i+1];
    a2 = C[i+1] - a1;

    aux[i] = a1;
    aux[i+1] = a2;
  }
}

void alg_k128_first_step(uint8_t C[], uint8_t B[], uint8_t k[]){

  C[0] = B[0] ^ k[0];
  C[1] = B[1] + k[1];
  C[2] = B[2] + k[2];
  C[3] = B[3] ^ k[3];
  C[4] = B[4] ^ k[4];
  C[5] = B[5] + k[5];
  C[6] = B[6] + k[6];
  C[7] = B[7] ^ k[7];
}

void alg_k128_reverse_first_step(uint8_t C[], uint8_t B[], uint8_t k[]){

  C[0] = B[0] ^ k[0];
  C[1] = B[1] - k[1];
  C[2] = B[2] - k[2];
  C[3] = B[3] ^ k[3];
  C[4] = B[4] ^ k[4];
  C[5] = B[5] - k[5];
  C[6] = B[6] - k[6];
  C[7] = B[7] ^ k[7];
}

void alg_k128_second_step(uint8_t C[]){

  C[0] = powers[C[0]];
  C[1] = logs[C[1]];
  C[2] = logs[C[2]];
  C[3] = powers[C[3]];
  C[4] = powers[C[4]];
  C[5] = logs[C[5]];
  C[6] = logs[C[6]];
  C[7] = powers[C[7]];
}

void alg_k128_reverse_second_step(uint8_t C[]){

  C[0] = logs[C[0]];
  C[1] = powers[C[1]];
  C[2] = powers[C[2]];
  C[3] = logs[C[3]];
  C[4] = logs[C[4]];
  C[5] = powers[C[5]];
  C[6] = powers[C[6]];
  C[7] = logs[C[7]];
}

void alg_k128_third_step(uint8_t C[], uint8_t k[]){

  C[0] = C[0] + k[0];
  C[1] = C[1] ^ k[1];
  C[2] = C[2] ^ k[2];
  C[3] = C[3] + k[3];
  C[4] = C[4] + k[4];
  C[5] = C[5] ^ k[5];
  C[6] = C[6] ^ k[6];
  C[7] = C[7] + k[7];
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
  for(i=0; i<8; i++) C[i] = aux[i];
  free(aux);
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
  for(i=0; i<8; i++) C[i] = aux[i];

  free(aux);
}

void alg_k128_final_transformation(uint8_t C[], uint8_t k[]){

  C[0] = C[0] ^ k[0];
  C[1] = C[1] + k[1];
  C[2] = C[2] + k[2];
  C[3] = C[3] ^ k[3];
  C[4] = C[4] ^ k[4];
  C[5] = C[5] + k[5];
  C[6] = C[6] + k[6];
  C[7] = C[7] ^ k[7];
}

void alg_k128_reverse_final_transformation(uint8_t C[], uint8_t k[]){

  C[0] = C[0] ^ k[0];
  C[1] = C[1] - k[1];
  C[2] = C[2] - k[2];
  C[3] = C[3] ^ k[3];
  C[4] = C[4] ^ k[4];
  C[5] = C[5] - k[5];
  C[6] = C[6] - k[6];
  C[7] = C[7] ^ k[7];
}

void alg_k128_iteration(int r, uint64_t keys[], byte_t file_bytes[]){

  uint8_t * k1 = number_to_array(keys[(2*r - 1)]);
  uint8_t * k2 = number_to_array(keys[(2*r)]);

  alg_k128_first_step(file_bytes, file_bytes, k1);
  alg_k128_second_step(file_bytes);
  alg_k128_third_step(file_bytes, k2);
  alg_k128_fourth_step(file_bytes);

  free(k1);
  free(k2);
}

void alg_k128_decript_iteration(int r, uint64_t keys[], byte_t file_bytes[]){
  uint8_t * k1 = number_to_array(keys[(2*r - 1)]);
  uint8_t * k2 = number_to_array(keys[(2*r)]);

  alg_k128_reverse_fourth_step(file_bytes);
  alg_k128_reverse_third_step(file_bytes, k2);
  alg_k128_reverse_second_step(file_bytes);
  alg_k128_reverse_first_step(file_bytes, file_bytes, k1);

  free(k1);
  free(k2);
}

void alg_k128(uint64_t keys[], byte_t file_bytes[]){

  int r, R = 12;
  uint8_t * final_key = number_to_array(keys[(2*R + 1)]);

  for(r=1;r<=R;r++) alg_k128_iteration(r, keys, file_bytes);

  alg_k128_final_transformation(file_bytes, final_key);
}

void alg_k128_reverse(uint64_t keys[], byte_t file_bytes[]){

  int r, R = 12;
  uint8_t * final_key = number_to_array(keys[(2*R + 1)]);

  alg_k128_reverse_final_transformation(file_bytes, final_key);
  for(r=R;r>=1;r--) alg_k128_decript_iteration(r, keys, file_bytes);
}

void f_k128_CBC(uint64_t keys[], byte_t file_bytes[], byte_t Yj[], int blocks){

  int i;

  i=0;

  /* FIRST 64 BITS */
  file_bytes[i + 0] = file_bytes[i + 0] ^ Yj[0];
  file_bytes[i + 1] = file_bytes[i + 1] ^ Yj[1];
  file_bytes[i + 2] = file_bytes[i + 2] ^ Yj[2];
  file_bytes[i + 3] = file_bytes[i + 3] ^ Yj[3];
  file_bytes[i + 4] = file_bytes[i + 4] ^ Yj[4];
  file_bytes[i + 5] = file_bytes[i + 5] ^ Yj[5];
  file_bytes[i + 6] = file_bytes[i + 6] ^ Yj[6];
  file_bytes[i + 7] = file_bytes[i + 7] ^ Yj[7];

  alg_k128(keys, file_bytes);

  Yj[0] = file_bytes[i+0];
  Yj[1] = file_bytes[i+1];
  Yj[2] = file_bytes[i+2];
  Yj[3] = file_bytes[i+3];
  Yj[4] = file_bytes[i+4];
  Yj[5] = file_bytes[i+5];
  Yj[6] = file_bytes[i+6];
  Yj[7] = file_bytes[i+7];

  /* OTHER 64 BITS */
  for(i=8; i<blocks*8; i=i+8){

    file_bytes[i + 0] = file_bytes[i + 0] ^ Yj[0];
    file_bytes[i + 1] = file_bytes[i + 1] ^ Yj[1];
    file_bytes[i + 2] = file_bytes[i + 2] ^ Yj[2];
    file_bytes[i + 3] = file_bytes[i + 3] ^ Yj[3];
    file_bytes[i + 4] = file_bytes[i + 4] ^ Yj[4];
    file_bytes[i + 5] = file_bytes[i + 5] ^ Yj[5];
    file_bytes[i + 6] = file_bytes[i + 6] ^ Yj[6];
    file_bytes[i + 7] = file_bytes[i + 7] ^ Yj[7];

    alg_k128(keys, file_bytes+i);

    Yj[0] = file_bytes[i+0];
    Yj[1] = file_bytes[i+1];
    Yj[2] = file_bytes[i+2];
    Yj[3] = file_bytes[i+3];
    Yj[4] = file_bytes[i+4];
    Yj[5] = file_bytes[i+5];
    Yj[6] = file_bytes[i+6];
    Yj[7] = file_bytes[i+7];
  }
}

void f_k128_CBC_reverse(uint64_t keys[], byte_t file_bytes[], byte_t Yj[], int blocks){

  int i, j;
  uint8_t CBC_aux[8];

  for(i=0; i<8; ++i) CBC_aux[i] = file_bytes[i];

  i = 0;

  alg_k128_reverse(keys, file_bytes + i);

  file_bytes[i+0] = file_bytes[i+0] ^ Yj[0];
  file_bytes[i+1] = file_bytes[i+1] ^ Yj[1];
  file_bytes[i+2] = file_bytes[i+2] ^ Yj[2];
  file_bytes[i+3] = file_bytes[i+3] ^ Yj[3];
  file_bytes[i+4] = file_bytes[i+4] ^ Yj[4];
  file_bytes[i+5] = file_bytes[i+5] ^ Yj[5];
  file_bytes[i+6] = file_bytes[i+6] ^ Yj[6];
  file_bytes[i+7] = file_bytes[i+7] ^ Yj[7];

  Yj[0] = CBC_aux[0];
  Yj[1] = CBC_aux[1];
  Yj[2] = CBC_aux[2];
  Yj[3] = CBC_aux[3];
  Yj[4] = CBC_aux[4];
  Yj[5] = CBC_aux[5];
  Yj[6] = CBC_aux[6];
  Yj[7] = CBC_aux[7];

  for(i=8; i<blocks*8; i=i+8){

    for(j=0; j<8; j++) CBC_aux[j] = file_bytes[i+j];

    alg_k128_reverse(keys, file_bytes+i);

    file_bytes[i+0] = file_bytes[i+0] ^ Yj[0];
    file_bytes[i+1] = file_bytes[i+1] ^ Yj[1];
    file_bytes[i+2] = file_bytes[i+2] ^ Yj[2];
    file_bytes[i+3] = file_bytes[i+3] ^ Yj[3];
    file_bytes[i+4] = file_bytes[i+4] ^ Yj[4];
    file_bytes[i+5] = file_bytes[i+5] ^ Yj[5];
    file_bytes[i+6] = file_bytes[i+6] ^ Yj[6];
    file_bytes[i+7] = file_bytes[i+7] ^ Yj[7];

    Yj[0] = CBC_aux[0];
    Yj[1] = CBC_aux[1];
    Yj[2] = CBC_aux[2];
    Yj[3] = CBC_aux[3];
    Yj[4] = CBC_aux[4];
    Yj[5] = CBC_aux[5];
    Yj[6] = CBC_aux[6];
    Yj[7] = CBC_aux[7];
  }
}
