pub mod auth;
pub mod enroll;
pub mod lockdown;
pub mod panic;
pub mod protect;
pub mod settings;
pub mod setup;

use serenity::all::{Context, GuildId};

pub async fn register_all(ctx: &Context, guild_id: GuildId) -> serenity::Result<()> {
    let commands: Vec<_> = setup::commands()
        .into_iter()
        .chain(protect::commands())
        .chain(settings::commands())
        .chain(enroll::commands())
        .chain(auth::commands())
        .chain(lockdown::commands())
        .collect();
    guild_id.set_commands(&ctx.http, commands).await?;
    Ok(())
}
