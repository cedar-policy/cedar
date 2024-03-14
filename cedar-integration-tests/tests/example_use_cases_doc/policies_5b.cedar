// Scenario 5B: Anyone can upload photos to albums in Alice's account as long as
// the photo is a JPEG or PNG with maximum size of 1MB. However, members of the
// group AVTeam can also create RAW files up to 100MB in size.
permit (
  principal,
  action == Action::"addPhoto",
  resource in Account::"alice"
)
when
{
  (["JPEG", "PNG"].contains(context.photo.filetype) &&
   context.photo.filesize_mb <= 1) ||
  (context.photo.filetype == "RAW" &&
   context.photo.filesize_mb <= 100 &&
   principal in UserGroup::"AVTeam")
};
