#include "portable-component-implementation.h"
#include "game-state.h"

static const struct { uint32_t slot; const char *name; } sounds[] = {
    {0,"boing.wav"}, {1,"effect.wav"}, {2,"bang.wav"}, {3,"ao-laser.wav"},
    {4,"bassdrum.wav"}, {5,"byeball.wav"}, {7,"wowpulse.wav"}, {8,"saucer.wav"},
    {9,"orchestr.wav"}, {10,"effect2.wav"}, {11,"sweepdow.wav"}, {12,"peow!.wav"},
    {13,"fanfare.wav"}, {14,"padexplo.wav"}, {15,"ricochet.wav"}, {16,"swordswi.wav"},
    {17,"gunfire.wav"}, {18,"humm.wav"}, {19,"glass.wav"}, {20,"orchblas.wav"},
    {21,"voltage.wav"}, {22,"thudclap.wav"}, {30,"tank.wav"}, {31,"xplosht1.wav"}, {32,"xploshor.wav"}
};

void lifted_game_enter(spx_gameplay_scene_context_v5 *context,game_scene_state *state) {
    const spx_gameplay_scene_services_v5 *s=context->services; void *user=s->context;
    progression_state *progress=state->progression; paddle_state *paddle=progress->paddle;
    pickup_state *pickups=paddle->pickups; play_state *play=pickups->motion->play;
    scene_state *scene=play->menu->scene; title_state *title=scene->animation;
    asset_name background={"mbbkgrnd.pcx"}, balls={"mball2.sbk"}, font={"thefont.sbk"}, bolt={"bigbolt.pcx"};
    s->clear(user,state,title->flow->overlay,0);
    s->image(user,state,title->flow->overlay,&background,2,0,0);
    s->load_bank(user,state,0,1,&balls); s->select_bank(user,state,0);
    s->load_bank(user,state,1,0,&font); s->select_font(user,state,1);
    title->font->objects->banks[2].count=1; title->font->objects->banks[2].retained[0]=0;
    s->clear(user,state,title->back,0);
    s->image(user,state,title->back,&bolt,0,0,0);
    s->select_bank(user,state,2); s->create_sprite(user,state,1,0,0,159,479); s->select_bank(user,state,0);
    for (unsigned i=0;i<sizeof(sounds)/sizeof(*sounds);++i) {
        asset_name name={sounds[i].name}; s->load_sound(user,state,sounds[i].slot,&name);
    }
    play->paused=0; pickups->next_life=999999999; play->menu->score=0; pickups->lives=3;
    paddle->phase=paddle->last_tick=progress->bricks->board_index=0;
    s->load_board(user,state); s->restart(user,state); s->reset_damage(user,state);
    s->damage_background(user,state,title->back);
    s->damage_destination(user,state,scene->presentation_mode ? title->flow->primary : scene->flip);
}

void lifted_game_redraw(spx_gameplay_scene_context_v5 *context,game_scene_state *state) {
    const spx_gameplay_scene_services_v5 *s=context->services; void *user=s->context;
    play_state *play=state->progression->paddle->pickups->motion->play;
    scene_state *scene=play->menu->scene; title_state *title=scene->animation;
    font_rect full={0,0,640,480};
    s->clear(user,state,title->flow->primary,0); s->clear(user,state,title->back,0);
    s->blit(user,state,title->back,&full,title->flow->overlay,&full,0x01000000);
    s->draw_score(user,state); s->draw_board(user,state,0);
    if (play->paused==1) {
        static const unsigned char text[]="PAUSED"; font_bytes bytes={text};
        s->center(user,state,320,240,6,&bytes);
    }
    s->blit(user,state,title->flow->primary,&full,title->back,&full,0x01000000);
    if (play_signed(state->damage->capability)>0 && !scene->presentation_mode)
        s->blit(user,state,scene->flip,&full,title->back,&full,0x01000000);
}

void lifted_game_key(spx_gameplay_scene_context_v5 *context,game_scene_state *state,uint32_t key) {
    const spx_gameplay_scene_services_v5 *s=context->services; void *user=s->context;
    progression_state *progress=state->progression;
    motion_state *motion=progress->paddle->pickups->motion; play_state *play=motion->play;
    if (play->paused==1 || ((key&255)=='P' && !play->paused)) {
        play->paused=play->paused==1 ? 0 : 1;
        if (!progress->pending) s->fade(user,state,1,10,0,255,0);
        s->redraw_scene(user,state); s->fade(user,state,1,10,0,255,1); return;
    }
    switch (key&255) {
    case 'p':
        if (play->menu->input_ready) { motion->sticky=play->gun=0; motion->paddle_width=font_width(motion_sprite(motion,68)); }
        break;
    case 'q': if (play->menu->input_ready) motion->sticky=1; break;
    case 'r': if (play->menu->input_ready) play->gun=1; break;
    case 's': if (play->menu->input_ready) motion->paddle_width=font_width(motion_sprite(motion,68))*2; break;
    case 't': {
        static const char *const tracks[]={"12flight.mds","acker-gs.mds","brain.mds","ethno_pa.mds","freebee.mds","gmfigaro.mds"};
        uint32_t chosen=s->random(user,state,6); s->stop_music(user,state);
        if (chosen<6) { asset_name name={tracks[chosen]}; s->play_music(user,state,&name,1); }
        break;
    }
    case 'u': s->stop_music(user,state); break;
    case '{': state->stereo_direction*= -1.0; break;
    default: break;
    }
}
