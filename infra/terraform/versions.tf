terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0, < 9.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6"
    }
  }

  # Estado remoto (recomendado): crie o bucket antes e descomente.
  # backend "gcs" {
  #   bucket = "SEU-PROJETO-tfstate"
  #   prefix = "portal-colaborador"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
