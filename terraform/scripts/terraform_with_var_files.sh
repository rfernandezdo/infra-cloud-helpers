#!/bin/bash

function terraform_with_var_files() {
  if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Usage: terraform_with_var_files [OPTIONS]"
    echo "Options:"
    echo "  --dir DIR                Specify the directory containing .tfvars files"
    echo "  --action ACTION          Specify the Terraform action (plan, apply, destroy, import, test, output)"
    echo "  --auto AUTO              Specify 'auto' for auto-approve (optional)"
    echo "  --resource_address ADDR  Specify the resource address for import action (optional)"
    echo "  --resource_id ID         Specify the resource ID for import action (optional)"
    echo "  --workspace WORKSPACE    Specify the Terraform workspace (default: default)"
    echo "  --test-directory DIR     Specify the test directory for test action (default: ./tests/mock)"
    echo "  --recursive              Execute action recursively on each subdirectory"
    echo "  --log-file FILE          Specify log file for error logging (default: terraform_errors.log)"
    echo "  --continue-on-error      Continue processing other directories even if one fails"
    echo "  --help, -h               Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Single directory operations"
    echo "  terraform_with_var_files --action plan --dir ./webapps/linux_web_app/101-linux_web_app-simple"
    echo "  terraform_with_var_files --action apply --dir ./webapps/linux_web_app/101-linux_web_app-simple --auto auto"
    echo "  terraform_with_var_files --action destroy --dir ./webapps/linux_web_app/101-linux_web_app-simple --auto auto"
    echo "  terraform_with_var_files --action output --dir ./webapps/linux_web_app/101-linux_web_app-simple"
    echo ""
    echo "  # Recursive operations"
    echo "  terraform_with_var_files --action plan --dir ./webapps/linux_web_app --recursive"
    echo "  terraform_with_var_files --action apply --dir ./webapps/linux_web_app --recursive --auto auto"
    echo "  terraform_with_var_files --action destroy --dir ./webapps/linux_web_app --recursive --auto auto"
    echo "  terraform_with_var_files --action test --dir ./webapps/linux_web_app --recursive"
    echo "  terraform_with_var_files --action output --dir ./webapps/linux_web_app --recursive"
    echo ""
    echo "  # With custom log file and continue on error"
    echo "  terraform_with_var_files --action plan --dir ./webapps --recursive --log-file my_errors.log --continue-on-error"
    echo "  terraform_with_var_files --action destroy --dir ./webapps --recursive --auto auto --continue-on-error"
    return 0
  fi

  local dir=""
  local action=""
  local auto=""
  local resource_address=""
  local resource_id=""
  local workspace="default"
  local test_directory="./tests/mock"
  local recursive=false
  local log_file="terraform_errors.log"
  local continue_on_error=false

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --dir) dir="$2"; shift ;;
      --action) action="$2"; shift ;;
      --auto) auto="$2"; shift ;;
      --resource_address) resource_address="$2"; shift ;;
      --resource_id) resource_id="$2"; shift ;;
      --workspace) workspace="$2"; shift ;;
      --test-directory) test_directory="$2"; shift ;;
      --log-file) log_file="$2"; shift ;;
      --recursive) recursive=true ;;
      --continue-on-error) continue_on_error=true ;;
      *) echo "Unknown parameter passed: $1"; return 1 ;;
    esac
    shift
  done

  if [[ ! -d "$dir" ]]; then
    echo "El directorio especificado no existe: $dir"
    return 1
  fi

  if [[ "$action" != "plan" && "$action" != "apply" && "$action" != "destroy" && "$action" != "import" && "$action" != "test" && "$action" != "output" ]]; then
    echo "Acción no válida. Usa 'plan', 'apply', 'destroy', 'import', 'test' o 'output'."
    return 1
  fi

  # Initialize log file with timestamp
  echo "=== Terraform Operations Log - $(date) ===" > "$log_file"
  echo "Action: $action" >> "$log_file"
  echo "Directory: $dir" >> "$log_file"
  echo "Recursive: $recursive" >> "$log_file"
  echo "Workspace: $workspace" >> "$log_file"
  echo "Continue on error: $continue_on_error" >> "$log_file"
  echo "=========================================" >> "$log_file"
  echo "" >> "$log_file"

  # Function to log errors
  log_error() {
    local error_msg="$1"
    local directory="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [ERROR] $directory - $error_msg" | tee -a "$log_file"
  }

  # Function to log success
  log_success() {
    local success_msg="$1"
    local directory="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [SUCCESS] $directory - $success_msg" | tee -a "$log_file"
  }

  # Function to log info
  log_info() {
    local info_msg="$1"
    local directory="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [INFO] $directory - $info_msg" | tee -a "$log_file"
  }

  # Function to execute terraform for a single directory
  execute_terraform_single() {
    local target_dir="$1"
    local step_number="$2"
    local total_steps="$3"
    
    echo ""
    echo "=================================="
    if [[ -n "$step_number" && -n "$total_steps" ]]; then
      echo "[$step_number/$total_steps] Processing directory: $target_dir"
    else
      echo "Processing directory: $target_dir"
    fi
    echo "=================================="
    
    log_info "Starting processing" "$target_dir"
    
    # Check if directory has .tfvars files
    local var_files=()
    for file in "$target_dir"/*.tfvars; do
      if [[ -f "$file" ]]; then
        var_files+=("--var-file $file")
      fi
    done

    if [[ ${#var_files[@]} -eq 0 ]]; then
      log_error "No se encontraron archivos .tfvars en el directorio" "$target_dir"
      return 1
    fi

    log_info "Found ${#var_files[@]} .tfvars files" "$target_dir"

    # Execute terraform init
    echo "Inicializando Terraform..."
    local init_output=$(terraform init 2>&1)
    if [[ $? -ne 0 ]]; then
      log_error "Terraform init falló: $init_output" "$target_dir"
      echo -e "\033[31mLa inicialización de Terraform falló. Intentando con 'terraform init -upgrade'...\033[0m"
      
      local upgrade_output=$(terraform init -upgrade 2>&1)
      if [[ $? -ne 0 ]]; then
        log_error "Terraform init -upgrade también falló: $upgrade_output" "$target_dir"
        return 1
      else
        log_info "Terraform init -upgrade ejecutado exitosamente" "$target_dir"
        echo -e "\033[32m'Terraform init -upgrade' ejecutado exitosamente.\033[0m"
      fi
    else
      log_info "Terraform init ejecutado exitosamente" "$target_dir"
      echo -e "\033[32m'Terraform init' ejecutado exitosamente.\033[0m"
    fi

    # Select workspace
    echo "Seleccionando el workspace: $workspace"
    local workspace_output=$(terraform workspace select "$workspace" 2>&1 || terraform workspace new "$workspace" 2>&1)
    if [[ $? -ne 0 ]]; then
      log_error "La selección del workspace falló: $workspace_output" "$target_dir"
      return 1
    fi
    log_info "Workspace '$workspace' seleccionado correctamente" "$target_dir"

    # Validate terraform configuration
    echo "Validando la configuración de Terraform..."
    local validate_output=$(terraform validate 2>&1)
    if [[ $? -ne 0 ]]; then
      log_error "La validación de Terraform falló: $validate_output" "$target_dir"
      return 1
    fi
    log_info "Configuración de Terraform validada correctamente" "$target_dir"

    # Build and execute command
    local command="terraform $action ${var_files[@]}"
    
    if [[ "$action" == "test" ]]; then
      command="terraform test -test-directory=$test_directory ${var_files[@]}"
      echo "Executing terraform test for directory: $target_dir"
      echo "Test directory: $test_directory"
      log_info "Ejecutando comando: $command" "$target_dir"
    elif [[ "$action" == "output" ]]; then
      command="terraform output"
      echo "Executing terraform output for directory: $target_dir"
      log_info "Ejecutando comando: $command" "$target_dir"
    elif [[ "$action" == "import" ]]; then
      if [[ -z "$resource_address" || -z "$resource_id" ]]; then
        log_error "Para la acción 'import', se deben proporcionar la dirección del recurso y el ID del recurso" "$target_dir"
        return 1
      fi
      command="terraform $action ${var_files[@]} $resource_address $resource_id"
      log_info "Ejecutando comando: $command" "$target_dir"
    elif [[ "$auto" == "auto" && ( "$action" == "apply" || "$action" == "destroy" ) ]]; then
      command="$command -auto-approve"
      log_info "Ejecutando comando: $command" "$target_dir"
    else
      log_info "Ejecutando comando: $command" "$target_dir"
    fi

    echo "Ejecutando: $command"
    echo "----------------------------------------"
    
    # Create temporary file to capture output
    local temp_output=$(mktemp)
    
    # Execute command with real-time output and capture to file and log
    eval "$command" 2>&1 | tee "$temp_output" | tee -a "$log_file"
    local exit_code=${PIPESTATUS[0]}
    
    echo "----------------------------------------"
    
    # Read the captured output for analysis
    local cmd_output=$(cat "$temp_output")
    
    # Clean up temporary file
    rm -f "$temp_output"
    
    # Check for warnings and errors in output
    local has_warnings=false
    local has_errors=false
    
    if echo "$cmd_output" | grep -i "warning\|deprecated\|caution" > /dev/null; then
      has_warnings=true
    fi
    
    if echo "$cmd_output" | grep -i "error\|failed\|fatal" > /dev/null; then
      has_errors=true
    fi
    
    # Analyze results
    if [[ $exit_code -eq 0 ]]; then
      if [[ "$has_warnings" == true ]]; then
        echo "⚠️  $action completed with WARNINGS for: $target_dir"
        log_info "$action completed with WARNINGS" "$target_dir"
        
        # Show warning summary
        echo ""
        echo "Warning summary:"
        echo "$cmd_output" | grep -i "warning\|deprecated\|caution" | head -5
        echo ""
        
        if [[ "$action" == "test" ]]; then
          echo "✅ Test PASSED (with warnings) for: $target_dir"
          log_success "Test PASSED (with warnings)" "$target_dir"
        elif [[ "$action" == "output" ]]; then
          echo "✅ Output SUCCESSFUL (with warnings) for: $target_dir"
          log_success "Output SUCCESSFUL (with warnings)" "$target_dir"
        else
          echo "✅ $action SUCCESSFUL (with warnings) for: $target_dir"
          log_success "$action SUCCESSFUL (with warnings)" "$target_dir"
        fi
        return 0
      else
        if [[ "$action" == "test" ]]; then
          echo "✅ Test PASSED for: $target_dir"
          log_success "Test PASSED" "$target_dir"
        elif [[ "$action" == "output" ]]; then
          echo "✅ Output SUCCESSFUL for: $target_dir"
          log_success "Output SUCCESSFUL" "$target_dir"
        else
          echo "✅ $action SUCCESSFUL for: $target_dir"
          log_success "$action SUCCESSFUL" "$target_dir"
        fi
        return 0
      fi
    else
      if [[ "$action" == "test" ]]; then
        echo "❌ Test FAILED for: $target_dir (Exit code: $exit_code)"
        log_error "Test FAILED - Exit code: $exit_code" "$target_dir"
      elif [[ "$action" == "output" ]]; then
        echo "❌ Output FAILED for: $target_dir (Exit code: $exit_code)"
        log_error "Output FAILED - Exit code: $exit_code" "$target_dir"
      else
        echo "❌ $action FAILED for: $target_dir (Exit code: $exit_code)"
        log_error "$action FAILED - Exit code: $exit_code" "$target_dir"
      fi
      
      # Show error summary
      if [[ "$has_errors" == true ]]; then
        echo ""
        echo "Error summary:"
        echo "$cmd_output" | grep -i "error\|failed\|fatal" | head -5
        echo ""
      fi
      
      return 1
    fi
  }

  # Main execution logic
  if [[ "$recursive" == true ]]; then
    echo "Ejecutando $action recursivamente en subdirectorios de: $dir"
    echo "Log file: $log_file"
    echo ""
    
    local failed_dirs=()
    local success_dirs=()
    local total_dirs=0
    local processed_dirs=()
    
    # First, collect all directories that have .tfvars files
    for subdir in "$dir"/*; do
      if [[ -d "$subdir" ]]; then
        local has_tfvars=false
        for file in "$subdir"/*.tfvars; do
          if [[ -f "$file" ]]; then
            has_tfvars=true
            break
          fi
        done
        
        if [[ "$has_tfvars" == true ]]; then
          processed_dirs+=("$subdir")
          total_dirs=$((total_dirs + 1))
        fi
      fi
    done
    
    if [[ $total_dirs -eq 0 ]]; then
      echo "❌ No se encontraron subdirectorios con archivos .tfvars"
      log_error "No se encontraron subdirectorios con archivos .tfvars" "$dir"
      return 1
    fi
    
    log_info "Iniciando procesamiento recursivo de $total_dirs directorios" "$dir"
    
    # Process each directory
    local current_step=1
    for subdir in "${processed_dirs[@]}"; do
      if execute_terraform_single "$subdir" "$current_step" "$total_dirs"; then
        success_dirs+=("$subdir")
      else
        failed_dirs+=("$subdir")
        
        if [[ "$continue_on_error" == false ]]; then
          echo ""
          echo "❌ Stopping execution due to error in: $subdir"
          echo "Use --continue-on-error to continue processing other directories"
          break
        fi
      fi
      current_step=$((current_step + 1))
    done
    
    # Summary report
    echo ""
    echo "=================================="
    echo "SUMMARY REPORT"
    echo "=================================="
    echo "Total directories: $total_dirs"
    echo "Processed: $((current_step - 1))"
    echo "Successful: ${#success_dirs[@]}"
    echo "Failed: ${#failed_dirs[@]}"
    echo "Log file: $log_file"
    echo ""
    
    if [[ ${#success_dirs[@]} -gt 0 ]]; then
      echo "✅ Successful directories:"
      for dir in "${success_dirs[@]}"; do
        echo "  - $dir"
      done
      echo ""
    fi
    
    if [[ ${#failed_dirs[@]} -gt 0 ]]; then
      echo "❌ Failed directories:"
      for dir in "${failed_dirs[@]}"; do
        echo "  - $dir"
      done
      echo ""
      echo "❌ Check log file for detailed error information: $log_file"
      
      # Show summary of errors
      echo "Error summary:"
      grep "\[ERROR\]" "$log_file" | tail -10
      
      return 1
    else
      echo "🎉 All operations completed successfully!"
      log_success "All recursive operations completed successfully" "$dir"
      return 0
    fi
  else
    # Single directory execution
    execute_terraform_single "$dir"
  fi
}

# Uso de la función
# terraform_with_var_files --dir "/ruta/al/directorio" --action "plan" --workspace "workspace"
# terraform_with_var_files --dir "/ruta/al/directorio" --action "apply" --auto "auto" --workspace "workspace"
# terraform_with_var_files --dir "/ruta/al/directorio" --action "destroy" --auto "auto" --workspace "workspace"
# terraform_with_var_files --dir "/ruta/al/directorio" --action "import" --resource_address "resource_address" --resource_id "resource_id" --workspace "workspace"
# 
# Nuevos ejemplos con funcionalidad recursiva y logging:
# terraform_with_var_files --dir "/ruta/al/directorio" --action "plan" --recursive --log-file "my_errors.log"
# terraform_with_var_files --dir "/ruta/al/directorio" --action "apply" --recursive --auto "auto" --continue-on-error
# terraform_with_var_files --dir "/ruta/al/directorio" --action "destroy" --recursive --auto "auto" --continue-on-error
# terraform_with_var_files --dir "/ruta/al/directorio" --action "test" --recursive --log-file "test_results.log"