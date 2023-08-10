// Scenario 4A: The album device_prototypes is viewable by anyone in the
// department HardwareEngineering with job level at least 5
permit (
  principal,
  action in [Action::"listPhotos", Action::"view"],
  resource in Album::"device_prototypes"
)
when
{ principal.department == "HardwareEngineering" && principal.jobLevel >= 5 };
