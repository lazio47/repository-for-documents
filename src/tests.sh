#!/bin/bash

set +e

# Função para verificar o resultado do comando
check_result() {
    if [ $? -eq 0 ]; then
        echo "✅ SUCESSO: $1"
    else
        echo "❌ FALHA: $1"
    fi
    # read -p "Press Enter to continue..."
}

echo "==== Início dos Testes ===="

printf "\n"
echo '1. Criar Credenciais para o Administrador'
echo "Teste: Criação de Credenciais para Administrador"
ADMIN_PASSWORD="adminpassword"
ADMIN_CREDENTIALS_FILE="admin_credentials.json"
./rep_subject_credentials "$ADMIN_PASSWORD" "$ADMIN_CREDENTIALS_FILE" 
check_result "Criação de Credenciais para Administrador"

printf "\n"
echo '2. Criar Organização'
echo "Teste: Criação de Organização"
ORG_NAME="MyTestOrg"
ADMIN_USERNAME="admin_user"
ADMIN_NAME="Admin User"
ADMIN_EMAIL="admin@mytestorg.com"
PUB_KEY_FILE="$ADMIN_CREDENTIALS_FILE"
./rep_create_org "$ORG_NAME" "$ADMIN_USERNAME" "$ADMIN_NAME" "$ADMIN_EMAIL" "$PUB_KEY_FILE" 
check_result "Criação de Organização"

printf "\n"
echo '3. Criar Sessão'
echo "Teste: Criação de Sessão"
SESSION_FILE="admin_session.json"
./rep_create_session "$ORG_NAME" "$ADMIN_USERNAME" "$ADMIN_PASSWORD" "$ADMIN_CREDENTIALS_FILE" "$SESSION_FILE" 
check_result "Criação de Sessão"

printf "\n"
echo '4. Criar Credenciais e Adicionar Sujeito (Sucesso)'
echo "Teste: Criar Credenciais e Adicionar Sujeito"
NEW_USER="user_test1"
NEW_USER_PASSWORD="userpassword1"
NEW_USER_NAME="User Test One"
NEW_USER_EMAIL="usertest1@test.com"
NEW_USER_CRED="user_test1_credentials.json"
./rep_subject_credentials "$NEW_USER_PASSWORD" "$NEW_USER_CRED"
check_result "Criação de Credenciais para $NEW_USER"
./rep_add_subject "$SESSION_FILE" "$NEW_USER" "$NEW_USER_NAME" "$NEW_USER_EMAIL" "$NEW_USER_CRED" 
check_result "Adicionar Sujeito $NEW_USER"

printf "\n"
echo '5. Adicionar Sujeito (Falha - usuário existente)'
echo "Teste: Adicionar Sujeito (Falha - Usuário Existente)"
./rep_add_subject "$SESSION_FILE" "$NEW_USER" "$NEW_USER_NAME" "$NEW_USER_EMAIL" "$NEW_USER_CRED" 
check_result "Adicionar Sujeito (Falha - Usuário Existente)"

printf "\n"
echo '6. Listar Sujeitos'
echo "Teste: Listar Sujeitos"
./rep_list_subjects "$SESSION_FILE"
check_result "Listar Sujeitos"

printf "\n"
echo '7. Adicionar Documento'
echo "Teste: Adicionar Documento"
DOC_NAME="FinanceReport"
FILE_CONTENT="finance_report.txt"
echo "Relatório financeiro de teste" > "$FILE_CONTENT"
./rep_add_doc "$SESSION_FILE" "$DOC_NAME" "$FILE_CONTENT"
check_result "Adicionar Documento"
rm "$FILE_CONTENT"

printf "\n"
echo '8. Listar Documentos'
echo "Teste: Listar Documentos"
./rep_list_docs "$SESSION_FILE"
check_result "Listar Documentos"

printf "\n"
echo '9. Obter Metadados do Documento (Sucesso)'
echo "Teste: Obter Metadados do Documento (Sucesso)"
./rep_get_doc_metadata "$SESSION_FILE" "$DOC_NAME"
check_result "Obter Metadados do Documento (Sucesso)"

printf "\n"
echo '10. Obter Metadados do Documento (Falha - Nome Inválido)'
echo "Teste: Obter Metadados do Documento (Falha - Nome Inválido)"
./rep_get_doc_metadata "$SESSION_FILE" "InvalidDoc" 
check_result "Obter Metadados do Documento (Falha - Nome Inválido)"

printf "\n"
echo '11. Deletar Documento'
echo "Teste: Deletar Documento"
./rep_delete_doc "$SESSION_FILE" "$DOC_NAME" 
check_result "Deletar Documento"

printf "\n"
echo '12. Deletar Documento (Falha - Documento Já Deletado)'
echo "Teste: Deletar Documento (Falha - Documento Já Deletado)"
./rep_delete_doc "$SESSION_FILE" "$DOC_NAME" 
check_result "Deletar Documento (Falha - Documento Já Deletado)"

printf "\n"
echo '13. Suspender Sujeito'
echo "Teste: Suspender Sujeito"
./rep_suspend_subject "$SESSION_FILE" "$NEW_USER" 
check_result "Suspender Sujeito"

printf "\n"
echo '14. Reativar Sujeito'
echo "Teste: Reativar Sujeito"
./rep_activate_subject "$SESSION_FILE" "$NEW_USER" 
check_result "Reativar Sujeito"

printf "\n"
echo '15. Modificar ACL de Documento'
echo "Teste: Modificar ACL de Documento"
DOC_ROLE="Readers"
DOC_PERMISSION="DOC_READ"
./rep_acl_doc "$SESSION_FILE" "$DOC_NAME" "+" "$DOC_ROLE" "$DOC_PERMISSION" 
check_result "Modificar ACL de Documento"

printf "\n"
echo '16. Suspender Role (Falha - Role Inexistente)'
echo "Teste: Suspender Role (Falha - Role Inexistente)"
ROLE_NAME="NonExistentRole"
./rep_suspend_role "$SESSION_FILE" "$ROLE_NAME" 
check_result "Suspender Role (Falha - Role Inexistente)"

printf "\n"
echo '17. Adicionar Documento'
echo "Teste: Adicionar Documento"
DOC_NAME="hello_world_program"
DOC_FILE="HelloWorld.java"

printf "\n"
echo 'Criar um arquivo de teste para o documento'
echo "public class HelloWorld {" > "$DOC_FILE"
echo "    public static void main(String[] args) {" >> "$DOC_FILE"
echo "        System.out.println(\"Hello, World!\");" >> "$DOC_FILE"
echo "    }" >> "$DOC_FILE"
echo "}" >> "$DOC_FILE"

./rep_add_doc "$SESSION_FILE" "$DOC_NAME" "$DOC_FILE"
check_result "Adicionar Documento"

printf "\n"
echo '18. Obter Arquivo do Documento'
echo "Teste: Obter Arquivo do Documento (Padrão)"
./rep_get_doc_file "$SESSION_FILE" "$DOC_NAME"
check_result "Obter Arquivo do Documento (Padrão)"

printf "\n"
echo '19. Obter Arquivo do Documento - Especificando Arquivo de Saída'
echo "Teste: Obter Arquivo do Documento (Especificando Arquivo de Saída)"
OUTPUT_FILE="HelloWorld_dec.java"
./rep_get_doc_file "$SESSION_FILE" "$DOC_NAME" "$OUTPUT_FILE"
check_result "Obter Arquivo do Documento (Especificando Arquivo de Saída)"

printf "\n"
echo '20. Testar Leitura do Arquivo Obtido'
echo "Teste: Validar Conteúdo do Arquivo Obtido"
if cmp -s "$DOC_FILE" "$OUTPUT_FILE"; then
    echo "✅ SUCESSO: O conteúdo do arquivo obtido corresponde ao original."
else
    echo "❌ FALHA: O conteúdo do arquivo obtido não corresponde ao original."
fi

printf "\n"
echo '21. Testar Obtenção de Documento Inexistente'
echo "Teste: Obter Documento Inexistente"
INVALID_DOC_NAME="non_existent_program"
./rep_get_doc_file "$SESSION_FILE" "$INVALID_DOC_NAME" 
check_result "Obter Documento Inexistente"


printf "\n"
echo '22. Suspender Admin - Falha: Único Manager'
echo "Teste: Suspender Admin"
./rep_suspend_subject "$SESSION_FILE" "$ADMIN_USERNAME" 
check_result "Suspender Admin"

printf "\n"
echo '23. Criar Role'
echo "Teste: Criar Role"
ROLE_NAME="new_role"
./rep_add_role "$SESSION_FILE" "$ROLE_NAME" 
check_result "Criar Role"

printf "\n"
echo '24. Listar Roles'
echo "Teste: Listar Roles"
./rep_list_roles "$SESSION_FILE" 
check_result "Listar Roles"

printf "\n"
echo '26. Suspender Role'
echo "Teste: Suspender Role"
./rep_suspend_role "$SESSION_FILE" "$ROLE_NAME" 
check_result "Suspender Role"

printf "\n"
echo '27. Reactivar Role'
echo "Teste: Reactivar Role"
./rep_reactivate_role "$SESSION_FILE" "$ROLE_NAME" 
check_result "Reactivar Role"

printf "\n"
echo '28. Adicionar Permissão'
echo "Teste: Adicionar Permissão"
PERMISSION="DOC_NEW"
./rep_add_permission "$SESSION_FILE" "$ROLE_NAME" "$PERMISSION" 
check_result "Adicionar Permissão"

printf "\n"
echo '29. Adicionar Subject em Role'
echo "Teste: Adicionar Subject em Role"
./rep_add_permission "$SESSION_FILE" "$ROLE_NAME" "$NEW_USER" 
check_result "Adicionar Subject em Role"

printf "\n"
echo '30. Listar Permissões'
echo "Teste: Listar Permissões"
./rep_list_role_permissions "$SESSION_FILE" "$ROLE_NAME" 
check_result "Listar Permissões"

printf "\n"
echo "31. Listar Roles"
echo "Teste: Listar Roles com DOC_NEW"
./rep_list_permission_roles "$SESSION_FILE" "$PERMISSION" 
check_result "Listar Roles com DOC_NEW"

printf "\n"
echo '32. Listar Subjects de uma Role'
echo "Teste: Listar Subjects de uma Role"
./rep_list_role_subjects "$SESSION_FILE" "$ROLE_NAME" 
check_result "Listar Subjects de uma Role"

printf "\n"
echo "33. Listar Roles de um Subject"
echo "Teste: Listar Roles de um Subject"
./rep_list_subject_roles "$SESSION_FILE" "$NEW_USER" 
check_result "Listar Roles de um Subject"

printf "\n"
echo '34. Remover Permissão'
echo "Teste: Remover Permissão"
./rep_remove_permission "$SESSION_FILE" "$ROLE_NAME" "$PERMISSION" 
check_result "Listar Roles de um Subject"

printf "\n"
echo '35. Remover Subject de uma role'
echo "Teste: Remover Subject de uma role"
./rep_remove_permission "$SESSION_FILE" "$ROLE_NAME" "$NEW_USER" 
check_result "Remover Subject de uma role"

printf "\n"
echo '36. Criar Organização (Falha - Nome Duplicado)'
echo "Teste: Criar Organização (Falha - Nome Duplicado)"
./rep_create_org "$ORG_NAME" "$ADMIN_USERNAME" "$ADMIN_NAME" "$ADMIN_EMAIL" "$PUB_KEY_FILE"
check_result "Criar Organização (Falha - Nome Duplicado)"

printf "\n"
echo '37. Obter Metadados de Documento Excluído'
echo "Teste: Obter Metadados de Documento Excluído"
./rep_get_doc_metadata "$SESSION_FILE" "$DOC_NAME"
check_result "Obter Metadados de Documento Excluído"

printf "\n"
echo '38. NEW_USER Adiciona Documento com Sucesso'
echo "Teste: NEW_USER Adiciona Documento com Sucesso"
NEW_USER_DOC_NAME="UserTestDoc"
NEW_USER_DOC_CONTENT="user_test_doc.txt"
NEW_USER_SESSION_FILE="user_session.json"

# Criar sessão para NEW_USER
./rep_create_session "$ORG_NAME" "$NEW_USER" "$NEW_USER_PASSWORD" "$NEW_USER_CRED" "$NEW_USER_SESSION_FILE"
check_result "Criar Sessão para NEW_USER"

# Criar um documento pelo NEW_USER
echo "Conteúdo do documento criado pelo NEW_USER" > "$NEW_USER_DOC_CONTENT"
./rep_add_doc "$NEW_USER_SESSION_FILE" "$NEW_USER_DOC_NAME" "$NEW_USER_DOC_CONTENT"
check_result "NEW_USER Adicionar Documento"

printf "\n"
echo '39. Admin Lista Todos os Documentos'
echo "Teste: Admin Lista Todos os Documentos"
./rep_list_docs "$SESSION_FILE"
check_result "Admin Lista Todos os Documentos"

printf "\n"
echo '40. Listar Roles de NEW_USER'
echo "Teste: Listar Roles de NEW_USER"
./rep_list_subject_roles "$SESSION_FILE" "$NEW_USER"
check_result "Listar Roles de NEW_USER"


printf "\n"
echo '41. NEW_USER Tenta Obter Documento (Falha - Ausência de Permissão)'
echo "Teste: NEW_USER Tenta Obter Documento (Falha - Ausência de Permissão)"
./rep_get_doc_file "$NEW_USER_SESSION_FILE" "$NEW_USER_DOC_NAME" 
check_result "NEW_USER Tenta Obter Documento (Falha - Ausência de Permissão)"

printf "\n"
echo '42. Admin Concede Permissão para NEW_USER'
echo "Teste: Admin Concede Permissão para NEW_USER"
DOC_ROLE="Readers"
DOC_PERMISSION="DOC_READ"
./rep_acl_doc "$SESSION_FILE" "$NEW_USER_DOC_NAME" "+" "$DOC_ROLE" "$DOC_PERMISSION"
check_result "Admin Concede Permissão para NEW_USER"

printf "\n"
echo '43. Adicionar Subject em Role'
echo "Teste: Adicionar Subject em Role"
./rep_add_permission "$SESSION_FILE" "$DOC_ROLE" "$NEW_USER" 
check_result "Adicionar Subject em Role"

printf "\n"
echo '44. Listar Roles de NEW_USER'
echo "Teste: Listar Roles de NEW_USER"
./rep_list_subject_roles "$SESSION_FILE" "$NEW_USER"
check_result "Listar Roles de NEW_USER"

printf "\n"
echo '45. Listar Permissions da Role Readers'
echo "Teste: Listar Permissions da Role Readers"
./rep_list_role_permissions "$SESSION_FILE" "$DOC_ROLE"
check_result "Listar Permissions da Role Readers"

printf "\n"
echo '46. Alterar permissoes de uma role'
echo "Teste: Alterar permissoes de uma role por parte do novo cliente"
./rep_acl_doc "$NEW_USER_SESSION_FILE" "$DOC_NAME" "+" "$DOC_ROLE" "$DOC_PERMISSION"
check_result "Falha por ausencia de permissoes"

# Limpeza
rm -f "$DOC_FILE" "$OUTPUT_FILE"
rm "$NEW_USER_DOC_CONTENT"

echo "==== Fim dos Testes ===="
