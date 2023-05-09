// Only members of the HardwareEngineering department with job level >= 5 can
// view photos in device_prototypes
@id("prototypes access policy")
permit (
  principal,
  action == Action::"view",
  resource in Album::"device_prototypes"
)
when
{ principal.department == "HardwareEngineering" && principal.jobLevel >= 5 };
