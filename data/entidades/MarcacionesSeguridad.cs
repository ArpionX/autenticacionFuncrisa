using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace Turnos.data.entidades;

[Table("Marcaciones_seguridad")]
public partial class MarcacionesSeguridad
{
    [Key]
    [Column("id")]
    public int Id { get; set; }

    [Column("numMarcacion")]
    public int NumMarcacion { get; set; }

    [Column("horaMarcacion", TypeName = "datetime")]
    public DateTime HoraMarcacion { get; set; }

    [Column("idHorario")]
    public int IdHorario { get; set; }

    [Column("activo")]
    public bool Activo { get; set; }

    [Column("completa")]
    public bool Completa { get; set; }

    [ForeignKey("IdHorario")]
    [InverseProperty("MarcacionesSeguridads")]
    public virtual HorarioSeguridad IdHorarioNavigation { get; set; } = null!;
}
