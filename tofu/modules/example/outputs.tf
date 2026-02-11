output "name" {
  description = "The generated pet name"
  value       = random_pet.this.id
}
