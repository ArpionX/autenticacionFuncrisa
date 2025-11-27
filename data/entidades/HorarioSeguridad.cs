using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace Turnos.data.entidades;

[Table("Horario_seguridad")]
public partial class HorarioSeguridad
{
    [Key]
    [Column("id")]
    public int Id { get; set; }

    [Column("dia")]
    public DateOnly Dia { get; set; }

    [Column("horaInicio")]
    public TimeOnly HoraInicio { get; set; }

    [Column("horaFin")]
    public TimeOnly HoraFin { get; set; }

    [Column("codigo")]
    [StringLength(10)]
    [Unicode(false)]
    public string Codigo { get; set; } = null!;

    [Column("empresa")]
    [StringLength(20)]
    [Unicode(false)]
    public string? Empresa { get; set; }

    [Column("activo")]
    public bool Activo { get; set; }

    [InverseProperty("IdHorarioNavigation")]
    public virtual ICollection<MarcacionesSeguridad> MarcacionesSeguridads { get; set; } = new List<MarcacionesSeguridad>();
}
