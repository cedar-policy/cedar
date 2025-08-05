// Subscriber Content Access (Shows)
@id("subscriber-content-access/show")
permit (
  principal is Subscriber,
  action == Action::"watch",
  resource is Show
)
unless
{ resource.isEarlyAccess && context.now.datetime < resource.releaseDate };

// Subscriber Content Access (Movies)
@id("subscriber-content-access/movie")
permit (
  principal is Subscriber,
  action == Action::"watch",
  resource is Movie
)
unless { resource.needsRentOrBuy };

// Free Content Access
@id("free-content-access")
permit (
  principal is FreeMember,
  action == Action::"watch",
  resource
)
when { resource.isFree };

// Promo: Rent/Buy Oscar-Nominated Movies Until the Oscars
@id("rent-buy-oscar-movie")
permit (
  principal is Subscriber,
  action in [Action::"rent", Action::"buy"],
  resource is Movie
)
when
{
  resource.isOscarNominated &&
  context.now.datetime >= datetime("2025-02-02T19:00:00-0500") &&
  context.now.datetime < datetime(
      "2025-03-02T19:00:00-0500"
    ) // Oscars Night
};

// Early Access (24h) to Shows for Premium Subscribers
@id("early-access-show")
permit (
  principal is Subscriber,
  action == Action::"watch",
  resource is Show
)
when
{
  resource.isEarlyAccess &&
  principal.subscription.tier == "premium" &&
  context.now.datetime >= resource.releaseDate.offset(duration("-24h"))
};

// Forbid Bedtime Access to Kid Profile
@id("forbid-bedtime-watch-kid-profile")
forbid (
  principal is Subscriber,
  action == Action::"watch",
  resource
)
when { principal.profile.isKid }
unless
{
  // `toTime()` returns the duration modulo one day (i.e., it ignores the "date"
  // component). Here, we use it to calculate the subscriber's local time and
  // compare the result against durations that represent 6:00AM and 9:00PM.
  duration("6h") <= context.now
    .datetime
    .offset
    (
      context.now.localTimeOffset
    )
    .toTime
    (
    ) &&
  context.now.datetime.offset(context.now.localTimeOffset).toTime() <= duration(
      "21h"
    )
};
