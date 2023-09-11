
// These are sample policies for testing the Cedar parser.

@test_annotation("This is the annotation")
permit(
  principal == User::"alice",
  action == PhotoOp::"view",
  resource == Photo::"VacationPhoto94.jpg"
);

@anno1("first annotation")
@anno2("second annotation")
permit(
  principal in Group::"jane_friends",
  action == PhotoOp::"view",
  resource == Photo::"VacationPhoto94.jpg"
);

permit(
  principal == User::"alice",
  action == PhotoOp::"view",
  resource in Album::"jane_vacation"
);

permit(
  principal == User::"alice",
  action in [PhotoOp::"view", PhotoOp::"edit", PhotoOp::"delete"],
  resource in Album::"jane_vacation"
);

// Alice has "admin" permissions on the album
permit(
  principal == User::"alice",
  action in PhotoflashRole::"admin",
  resource in Album::"jane_vacation"
);

// Solution #1: Using multiple policies
permit(
  principal == User::"alice",
  action in PhotoflashRole::"admin",
  resource in Album::"jane_vacation"
);

permit(
  principal == User::"alice",
  action == PhotoOp::"edit",
  resource in Album::"jane_vacation"
);

// Solution #2: Using conditions in a single policy.
// Note - depending on the implementation of a backend datastore,
// shifting rules into the conditions may result in changes to
// performance or search/lookup capabilities, as the condition clauses
// can be less amenable to indexing.
permit(
  principal == User::"alice",
  action,
  resource in Album::"jane_vacation"
)
when {
  action in PhotoflashRole::"viewer" ||
  action == PhotoOp::"edit"
};

permit(
  principal:User,
  action == PhotoOp::"view",
  resource in Album::"jane_vacation"
);

permit(
  principal,
  action == PhotoOp::"view",
  resource in Album::"jane_vacation"
);

permit(
  principal == User::"alice",
  action in [AccountOp::"listAlbums", AlbumOp::"listPhotos", PhotoOp::"view"],
  resource in Account::"jane"
);

permit(
  principal == User::"alice",
  action,
  resource:Photo in Account::"jane"
);

permit(
  principal:User,
  action in [AlbumOp::"listPhotos", PhotoOp::"view"],
  resource in Album::"device_prototypes"
)
when {
  principal.department == "HardwareEngineering" &&
  principal.jobLevel >= 10 &&
  (context.time.now - principal.hireDate).getDays() >= 365
};

permit(
  principal == User::"alice",
  action == PhotoOp::"view",
  resource:Photo
)
when {
  resource.fileType == "JPEG" &&
  (context.time.now - resource.creationDate).getDays() <= 7
};

permit(
  principal == User::"alice",
  action,
  resource
)
when {
  action.readOnly &&
  action.appliesTo in [Photo, Album]
};

permit(
  principal,
  action == PhotoOp::"view",
  resource
)
when {
  principal.department == resource.department
};

permit(
  principal,
  action,
  resource
)
when {
  principal == resource.owner
};

permit(
  principal,
  action in PhotoOp::"view",
  resource:Photo
)
when {
  principal.department == resource.owner.department
};

permit(
  principal,
  action,
  resource
)
when {
  principal == resource.owner ||
  (resource has admins && principal in resource.admins)
};

permit(
  principal == User::"alice",
  action in PhotoflashRole::"viewer",
  resource in Album::"vacation"
)
when {
  context.http.source_ip.inIpRange(ip("192.0.2.0/24")) &&
  context.authentication.acr in ["phr", "phrh"]
};

permit(
  principal,
  action == AlbumOp::"addPhoto",
  resource in Account::"jane"
)
when {
  (context.photo.filetype in ["JPEG", "PNG"] &&
   context.photo.filesize_mb <= 1)
  ||
  (context.photo.filetype == "RAW" &&
   context.photo.filesize_mb <= 100 &&
   principal in Group::"AVTeam")
};

forbid (
  principal == User::"alice",
  action,
  resource
)
unless {
  action.readOnly
}
when {
  context.time.now < timestamp("2022-01-01T10:15:00.021-05:00")
};

forbid (
  principal,
  action,
  resource in Account::"jane"
)
unless {
  context.http.authentication.acr == "phrh" &&
  (context.time.now - context.authentication.time).getMinutes() < 30
};

permit (
  principal == User::"alice",
  action in PhotoflashRole::"viewer",
  resource in Account::"jane"
)
advice {
  "Anonymize"
};

permit (
  principal == User::"alice",
  action in PhotoflashRole::"viewer",
  resource in Account::"jane"
)
advice {
  "{\"type\":\"PhotoFilterInstruction\", \"anonymize\":true}"
};

forbid (
  principal == User::"alice",
  action,
  resource
)
unless {
  action.readOnly
}
when {
  context.time.now < timestamp("2022-01-01T10:15:00.021-05:00")
}
advice {
  "Go to sleep! Remember to feed the cat in the morning."
};

// Allow everyone who used MFA
permit (
  principal,
  action,
  resource in Account::"jane"
)
when {
  context.authentication.usedMFA
};

// If no MFA and before Jan 1, allow with a warning
permit (
  principal,
  action,
  resource in Account::"jane"
)
when {
  context.time.now < timestamp("2022-01-01T00:00:00.000-05:00") &&
  !context.authentication.usedMFA
}
advice {
  "Notice: MFA will be required starting January 1"
};

// If no MFA and after Jan 1, block with an error message
forbid (
  principal,
  action,
  resource in Account::"jane"
)
when {
  context.time.now >= timestamp("2022-01-01T00:00:00.000-05:00") &&
  !context.authentication.usedMFA
}
advice {
  "MFA is required starting January 1"
};

permit(
  principal == User::"alice",
  action == TableOp::"read",
  resource in Database::"photoflash_data_lake"
);

permit(
  principal == User::"alice",
  action == TableOp::"read",
  resource == Table::"customers"
)
advice {
  "[hash(EmailAddress),
    filter(SubscriptionLevel, \"Enterprise\"),
    filter(Country, \"US\"]"
};

permit(
  principal == User::"alice",
  action == TableOp::"read",
  resource == Table::"customers"
)
when {
  ["customer_id", "creation_date", "subscription_level"].containsAll(context.query.columns)
};

permit (
  principal == User::"alice",
  action == TableOp::"read",
  resource == Table::"customers"
)
unless {
  context.query.columns.containsAny(["email_address", "billing_address"])
};

permit (
  principal,
  action == Table::"query",
  resource in Database::"photoflash_data_lake"
)
unless {
  context.query has pii_columns &&
  context.query.pii_columns.size() > 0 &&
  !principal.approved_for_pii
};

permit (
  principal:User,
  action in [ForumOp::"post", ForumOp::"comment"],
  resource in Forum::"nature_photography"
);

permit (
  principal in Group::"Forum.NaturePhotography.Member",
  action in [ForumOp::"post", ForumOp::"comment"],
  resource in Forum::"nature_photography"
);

// The owner of every forum can add up to N = 5 new custom roles
// for their forum.
permit(
  principal,
  action == Forum::"addRole",
  resource:Forum
)
when {
  principal == resource.owner &&
  size(resource.roles) <= 5
};

// The owner of the "Nature Photography" forum can add / remove members of
// the "SeniorModerator" role as long as the total number of
// Senior Moderators is at most 10.
permit(
  principal,
  action in [ForumOp::"addMemberToRole", ForumOp::"removeMemberFromRole"],
  resource == Forum::"nature_photography"
)
when {
  principal == resource.owner &&
  context.role == "SeniorModerator" &&
  (action == ForumOp::"removeMemberFromRole" || size(resource.roles["SeniorModerator"]) < 10)
};

// The owner and Senior Moderators can add / remove members of the "JuniorModerator"
// role, as long as the total number of Junior Moderators is at most 10.
permit(
  principal,
  action in [ForumOp::"addMemberToRole", ForumOp::"removeMemberFromRole"],
  resource == Forum::"nature_photography"
)
when {
  (principal == resource.owner || principal in resource.roles["SeniorModerator"]) &&
  context.role == "JuniorModerator" &&
  (action == ForumOp::"removeMemberFromRole" || size(resource.roles["JuniorModerator"]) < 10)
};

// Both JuniorModerators and SeniorModerators can remove themselves
// from the role.
permit(
  principal,
  action == ForumOp::"removeMemberFromRole",
  resource == Forum::"nature_photography"
)
when {
  context.removedMember == principal &&
  context.role in ["SeniorModerator", "JuniorModerator"]
};

// JuniorModerators can delete forum posts
permit(
  principal,
  action == ForumOp::"deletePost",
  resource == Forum::"nature_photography"
)
when {
  principal in resource.roles["JuniorModerator"]
};

// SeniorModerators can delete forum posts and update the forum configuration
permit(
  principal,
  action in [ForumOp::"deletePost", ForumOp::"updateConfiguration"],
  resource == Forum::"nature_photography"
)
when {
  principal in resource.roles["SeniorModerator"]
};

permit (
  principal,
  action,
  resource == Album::{uid: "772358b3-de11-42dc-8681-f0a32e34aab8"}
);

permit (
  principal,
  action,
  resource == Album::"772358b3-de11-42dc-8681-f0a32e34aab8"
);

permit (
  principal,
  action,
  resource == Album::{displayName: "vacation_photos"}
);

permit (
  principal,
  action,
  resource == Album::"vacation_photos" //Requires custom resolver
);

permit (
  principal,
  action,
  resource == Album::{uid: "772358b3-de11-42dc-8681-f0a32e34aab8",
                      displayName: "vacation_photos"}
);

permit (
  principal == IAM::User::{awsAccountId: "123456789012", userName: "alice"},
  action,
  resource
);

permit (
  principal == IAM::Principal::"arn:aws:iam::123456789012:user/alice",
  action,
  resource
);

permit (
  principal == IAM::Principal::"arn:aws:iam::12345678901:user/Dave",
  action == S3::Action::"PutObject",
  resource == S3::Bucket::"arn:aws:s3:::awsexamplebucket1"
);

permit (
  principal == IAM::Principal::"arn:aws:iam::12345678901:user/Dave",
  action in [S3::Action::"CreateBucket",
             S3::Action::"ListAllMyBuckets",
             S3::Action::"GetBucketLocation"],
  resource in Account::"12345678901"
);

permit (
  principal == IAM::Principal::"arn:aws:iam::12345678901:user/Dave",
  action in [S3::Action::"GetObjectVersion",
             S3::Action::"GetBucketAcl"],
  resource in S3::Bucket::"DOC-EXAMPLE-BUCKET1"
);

permit (
  principal == IAM::Principal::"arn:aws:iam::12345678901:user/Dave",
  action in [S3::Action::"GetObjectVersion",
             S3::Action::"GetBucketAcl"],
  resource in S3::Bucket::"DOC-EXAMPLE-BUCKET1"
);

forbid (
  principal == IAM::Principal::"arn:aws:iam::12345678901:user/Dave",
  action in [S3::Action::"DeleteObject",
            S3::Action::"DeleteObjectVersion",
            S3::Action::"PutLifecycleConfiguration"],
  resource in S3::Bucket::"DOC-EXAMPLE-BUCKET1"
);

permit (
  principal == IAM::Principal::"arn:aws:iam::12345678901:user/Dave",
  action == S3::Action::"GetAccountPublicAccessBlock",
  resource == Account::"12345678901"
);
