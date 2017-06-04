#!/bin/bash
# Script para testar
make clean
make

echo "Primeiro."
./epzao -c -i entrada -o saida -p teste1234 -a # Consertar o erro que dá quando a senha é grande!
# echo ""
# echo ""
# echo "Segundo."
# ./epzao -d -i entrada -o saida -p senhaS
# echo ""
# echo ""
# echo "Terceiro."
# ./epzao -1 -i entrada -p senha
# echo ""
# echo ""
# echo "Quarto."
# ./epzao -2 -i entrada -p senhaAleDois
