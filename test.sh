#!/bin/bash
# Script para testar
make clean
make

touch outputs/saida entrada
touch outputs/saida_foto
touch outputs/saida_enunciado

touch outputs/saida entrada_f
touch outputs/saida_foto_f
touch outputs/saida_enunciado_f

echo "Primeiro."
./epzao -c -i inputs/entrada -o outputs/saida_entrada -p teste1234 -a # Consertar o erro que dá quando a senha é grande!
./epzao -c -i inputs/foto.jpg -o outputs/saida_foto -p teste1234 -a
./epzao -c -i inputs/enunciado.pdf -o outputs/saida_enunciado -p teste1234 -a
# echo ""
# echo ""
echo "Segundo."
./epzao -d -i outputs/saida_entrada -o outputs/saida_entrada_f -p teste1234
./epzao -d -i outputs/saida_foto -o outputs/saida_foto_f -p teste1234
./epzao -d -i outputs/saida_enunciado -o outputs/saida_enunciado_f -p teste1234
# ./epzao -d -i entrada -o saida -p senhaS
echo ""
echo ""
echo "Terceiro."
./epzao -1 -i inputs/file_512 -p teste1234
./epzao -1 -i inputs/file_1024 -p teste1234
# echo ""
# echo ""
# echo "Quarto."
# ./epzao -2 -i entrada -p senhaAleDois
