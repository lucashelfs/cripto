#!/bin/bash
# Script para testar
make clean
make

touch saida entrada
touch saida_foto
touch saida_enunciado

touch saida entrada_f
touch saida_foto_f
touch saida_enunciado_f

echo "Primeiro."
./epzao -c -i entrada -o saida_entrada -p teste1234 -a # Consertar o erro que dá quando a senha é grande!
./epzao -c -i foto.jpg -o saida_foto -p teste1234 -a 
./epzao -c -i enunciado.pdf -o saida_enunciado -p teste1234 -a 
# echo ""
# echo ""
echo "Segundo."
./epzao -d -i saida_entrada_f -o saida -p teste1234
./epzao -d -i saida_foto_f -o saida -p teste1234
./epzao -d -i saida_enunciado -o saida_enunciado_f -p teste1234
# ./epzao -d -i entrada -o saida -p senhaS
# echo ""
# echo ""
# echo "Terceiro."
# ./epzao -1 -i entrada -p senha
# echo ""
# echo ""
# echo "Quarto."
# ./epzao -2 -i entrada -p senhaAleDois
